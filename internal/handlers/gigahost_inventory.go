package handlers

// Background reconciliation of the provider's server inventory against the
// panel's own server rows.
//
// The provider can delete a VPS the panel still lists and still dials. The panel
// had no record of the provider's view of the servers table, so this file keeps
// one: for every server a Gigahost deployment registered, it records whether the
// provider's inventory still lists it.
//
// The fail-safe direction is the whole point. An inventory read that failed,
// timed out or enumerated the account incompletely is not evidence of absence,
// and such a read changes nothing at all.
//
// A listing is also not the same thing as an account. A Gigahost API key can be
// limited to a list of server ids (`servers: {mode: "r", all: false, ids: [...]}`),
// and such a key's list endpoint is filtered: it answers 200 with a complete,
// self-consistent inventory of everything that key may see. The provider exposes
// no scope flag to a key-authenticated caller (key management is admin-only and
// GET /account carries no permissions), so the panel cannot tell a filtered read
// from an unfiltered one. It therefore never derives absence from a listing:
//
//   - a listed server is positive evidence and may clear a mark;
//   - an unlisted server is decided by a per-server read, where the provider does
//     distinguish "not there" (404, absence) from "not yours to see"
//     (401/403/400/405, inconclusive, state preserved).
//
// A server the provider lists again has the state cleared rather than staying
// marked absent.
//
// A successful read is evidence about one account only: the account that
// answered it. Each server row records the provider account it was provisioned
// under, and a read may judge a row only when the two agree. Pointing the panel
// at a second account therefore says nothing about the first account's rows -
// they keep their state - while a row whose association is unknown (it predates
// this rule, or the provider could not name the account at registration) is
// never judged by any read at all.
//
// This file reads the provider and writes one observation column per changed row.
// It never deletes a row, never rewrites an address or a credential, and never
// touches a session. It is safe to run repeatedly: in steady state no row
// changes, so a repeated pass performs no writes and preserves the original
// observation time.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// gigahostInventoryProvider is the provider name a deployment records in a
// server's protocols. Only rows carrying it are judged by this provider's
// inventory; an operator-added server is not the provider's to list or not list.
const gigahostInventoryProvider = "gigahost"

// gigahostInventoryTimeout bounds the inventory read so a provider that answers
// slowly cannot stall the background pass that drives it.
const gigahostInventoryTimeout = 30 * time.Second

// providerBackedServer is one panel row the provider provisioned, together with
// the state this pass may have to change.
type providerBackedServer struct {
	serverID         int64
	providerServerID int64
	// accountID is the provider account the row was provisioned under. Empty
	// means unknown, which no read may treat as a match.
	accountID string
	// absentAt is the stored observation, empty when the row is not marked absent.
	absentAt string
}

// gigahostInventoryAnswer is one successful inventory read: the provider server
// ids the account holds, the account that answered, and the client that answered
// so a server outside the listing can be asked about individually.
type gigahostInventoryAnswer struct {
	listed    map[int64]struct{}
	accountID string
	client    gigahost.Client
}

// gigahostServerVerdict is what one per-server read concluded about a server the
// inventory did not list.
type gigahostServerVerdict int

const (
	// gigahostServerUnmeasured means the provider did not answer for this server:
	// a refusal, a timeout, or an unusable answer. A refusal is what a key sees
	// for a server outside its visibility, so this says nothing about existence.
	gigahostServerUnmeasured gigahostServerVerdict = iota
	// gigahostServerAbsent means the provider answered that the server does not
	// exist for it. This is the only authoritative absence.
	gigahostServerAbsent
	// gigahostServerPresent means the provider answered about the server, so it
	// exists: the listing simply did not enumerate it for this key.
	gigahostServerPresent
)

// gigahostServerState asks the provider about one server.
//
// Only a 404 is absence. Every other failure - an authorization refusal for a
// server outside the key's visibility, a timeout, a malformed answer - is
// unmeasured, because those outcomes are exactly what a restricted key produces
// for a server that is running perfectly well.
func gigahostServerState(ctx context.Context, client gigahost.Client, serverID int64) gigahostServerVerdict {
	if client == nil || serverID <= 0 {
		return gigahostServerUnmeasured
	}
	if _, err := client.GetServer(ctx, serverID); err != nil {
		if errors.Is(err, gigahost.ErrNotFound) {
			return gigahostServerAbsent
		}
		return gigahostServerUnmeasured
	}
	return gigahostServerPresent
}

// ReconcileGigahostServerInventory records, for every Gigahost-provisioned
// server row, whether the provider's inventory still lists it.
//
// Nothing here is on a request path: the panel's periodic background pass calls
// it, so a slow or unreachable provider delays no page load. A pass is safe to
// repeat because it is a read followed by, at most, the writes that change a
// row's state, and each of those writes is idempotent.
//
// An error means the pass could not judge the rows, which is the fail-safe
// outcome: every row is left exactly as it was.
func (h *Handlers) ReconcileGigahostServerInventory(ctx context.Context) error {
	if h == nil || h.db == nil {
		return nil
	}
	rows, err := h.providerBackedServerRows(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		// No row was provisioned by this provider, so the inventory cannot answer
		// for anything and the read is not worth making.
		return nil
	}
	answer, err := h.gigahostInventoryAnswerFor(ctx)
	if err != nil {
		return err
	}
	return h.applyGigahostInventoryPresence(ctx, rows, answer)
}

// providerBackedServerRows returns the panel rows this provider's inventory can
// judge: a Gigahost-provisioned row that recorded the provider server id it was
// registered with. A row of another provider, an operator-added row and a
// provider row with no recorded id are all left out, because the inventory
// answers for none of them.
func (h *Handlers) providerBackedServerRows(ctx context.Context) ([]providerBackedServer, error) {
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read servers for the provider inventory reconciliation: %w", err)
	}
	rows := make([]providerBackedServer, 0, len(servers))
	for _, s := range servers {
		providerServerID, ok := providerBackedServerID(s.Protocols)
		if !ok {
			continue
		}
		rows = append(rows, providerBackedServer{
			serverID:         s.ID,
			providerServerID: providerServerID,
			accountID:        strings.TrimSpace(s.ProviderAccountID),
			absentAt:         s.ProviderAbsentAt,
		})
	}
	return rows, nil
}

// providerBackedServerID returns the provider server id a panel row was
// registered with, when the row is a Gigahost-provisioned row that carries one.
func providerBackedServerID(protocols map[string]any) (int64, bool) {
	if protocols == nil {
		return 0, false
	}
	provider, ok := protocols["provider"].(string)
	if !ok || !strings.EqualFold(strings.TrimSpace(provider), gigahostInventoryProvider) {
		return 0, false
	}
	return providerServerIDNumber(protocols["provider_server_id"])
}

// providerServerIDNumber reads a stored provider server id. A value that JSON
// round-tripped through the protocols blob can arrive as an integer or as text,
// so both shapes are accepted; anything else, and any non-positive id, is not an
// id the inventory can answer for.
func providerServerIDNumber(stored any) (int64, bool) {
	switch v := stored.(type) {
	case int64:
		return positiveID(v)
	case int:
		return positiveID(int64(v))
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return positiveID(int64(v))
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return positiveID(parsed)
	default:
		return 0, false
	}
}

// positiveID reports the id when it can name a provider server, which a zero or
// negative id cannot.
func positiveID(id int64) (int64, bool) {
	if id <= 0 {
		return 0, false
	}
	return id, true
}

// gigahostInventoryServerIDs performs the inventory read and returns the
// provider server ids it lists.
//
// Three outcomes are deliberately distinguished, and only one of them is
// evidence about a server the panel holds:
//
//   - an IDENTIFIED entry carries a positive provider server id. Only identified
//     entries contribute to the returned set.
//   - an UNIDENTIFIED entry carries no usable id: a null element, a missing id,
//     or an id the provider client could not parse. Such an entry names no
//     server, so a read containing one cannot say which servers the account
//     holds. The whole read is refused instead of dropping the entry, because a
//     dropped entry turns "this answer could not identify one row" into "the
//     provider does not have it" for every panel row the entry might have named -
//     a durable false deletion, which is the direction this must never fail in.
//   - an ABSENT ORDER is a panel row whose recorded provider server id is not in
//     the returned set of a fully identified read. Only that case is recorded
//     absent, by the caller. A read that enumerates the account and lists zero
//     servers is complete and identified, so it keeps this meaning: every
//     provider row is genuinely absent.
//
// A read that failed, timed out, or enumerated the account incompletely is
// reported the same way - as an error, with nothing written - because an
// unanswered or partial inventory is not evidence that any server is gone. The
// client already fails closed on a page that contradicts its own pagination
// metadata or a total that does not match what it aggregated.
func (h *Handlers) gigahostInventoryAnswerFor(ctx context.Context) (gigahostInventoryAnswer, error) {
	client, err := h.getGigahostClient(ctx, nil)
	if err != nil {
		return gigahostInventoryAnswer{}, fmt.Errorf("gigahost inventory reconciliation skipped; server rows unchanged: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, gigahostInventoryTimeout)
	defer cancel()

	// The account identity is resolved before the inventory because it decides
	// which rows this answer may judge. A read that cannot be attributed to an
	// account proves nothing about any row, so it is refused whole rather than
	// applied to every provider-backed row.
	account, err := client.GetAccount(callCtx)
	if err != nil {
		return gigahostInventoryAnswer{}, fmt.Errorf("gigahost account identity unavailable; server rows unchanged: %w", err)
	}
	accountID := gigahostAccountIdentity(account)
	if accountID == "" {
		// Not the same thing as an account without servers: the provider answered
		// but the identifier could not be read, so the pass is skipped and the
		// reason is returned for the background log rather than failing silently.
		return gigahostInventoryAnswer{}, errors.New(
			"gigahost GET /account answered without a usable account identifier (expected cust_id as a number or text); " +
				"server rows unchanged: an inventory read that cannot be attributed to an account proves nothing")
	}

	inventory, err := client.GetServers(callCtx)
	if err != nil {
		return gigahostInventoryAnswer{}, fmt.Errorf("gigahost inventory read failed; server rows unchanged: %w", err)
	}

	listed, err := gigahostIdentifiedServerIDs(inventory)
	if err != nil {
		return gigahostInventoryAnswer{}, err
	}
	return gigahostInventoryAnswer{listed: listed, accountID: accountID, client: client}, nil
}

// gigahostIdentifiedServerIDs returns the provider server ids of an inventory
// answer, or an error when any entry cannot be identified.
//
// It is the identity gate for the whole pass, and it is separate from the read so
// the rule is testable without a provider: every entry must name a positive
// provider server id, otherwise the answer is not usable as evidence about the
// account and nothing may be concluded from it.
func gigahostIdentifiedServerIDs(inventory []gigahost.ServerInfo) (map[int64]struct{}, error) {
	listed := make(map[int64]struct{}, len(inventory))
	for i, s := range inventory {
		if s.ID <= 0 {
			return nil, fmt.Errorf(
				"gigahost inventory entry %d of %d has no usable server id; server rows unchanged",
				i+1, len(inventory))
		}
		listed[s.ID] = struct{}{}
	}
	return listed, nil
}

// gigahostRowDecision is what one pass concluded about one row.
type gigahostRowDecision int

const (
	gigahostRowUnknownAccount gigahostRowDecision = iota
	gigahostRowOtherAccount
	gigahostRowUnmeasured
	gigahostRowPresent
	gigahostRowAbsent
	gigahostRowScopeEvidence
)

// presence reports whether the decision names an existence answer and, if it does,
// whether the server exists.
func (d gigahostRowDecision) presence() (present, measured bool) {
	switch d {
	case gigahostRowPresent, gigahostRowScopeEvidence:
		return true, true
	case gigahostRowAbsent:
		return false, true
	default:
		return false, false
	}
}

// decideGigahostRow applies the rule for one row against one answer: only a row of
// the answering account is judged, and only a per-server answer may say a server is
// gone.
func decideGigahostRow(ctx context.Context, row providerBackedServer, answer gigahostInventoryAnswer) gigahostRowDecision {
	if row.accountID == "" {
		return gigahostRowUnknownAccount
	}
	if row.accountID != answer.accountID {
		return gigahostRowOtherAccount
	}
	if _, listed := answer.listed[row.providerServerID]; listed {
		return gigahostRowPresent
	}
	switch gigahostServerState(ctx, answer.client, row.providerServerID) {
	case gigahostServerAbsent:
		return gigahostRowAbsent
	case gigahostServerPresent:
		return gigahostRowScopeEvidence
	default:
		return gigahostRowUnmeasured
	}
}

// applyGigahostInventoryPresence writes the provider's answer onto the rows whose
// state it changes. A row already carrying the answer is not rewritten, so the
// original observation time survives a repeated pass.
//
// A listed row is positive evidence and the only way the state is cleared. An
// unlisted row is never treated as absence on the strength of the listing: the
// provider is asked about that server, because a key that cannot see a server gets
// a refusal rather than a 404, and a refusal proves nothing.
func (h *Handlers) applyGigahostInventoryPresence(
	ctx context.Context, rows []providerBackedServer, answer gigahostInventoryAnswer,
) error {
	now := time.Now().UTC()
	var failures []error
	counts := make(map[gigahostRowDecision]int, len(rows))
	for _, row := range rows {
		decision := decideGigahostRow(ctx, row, answer)
		counts[decision]++
		present, measured := decision.presence()
		if !measured {
			continue
		}
		if err := h.writeProviderAbsence(ctx, row, present, now); err != nil {
			failures = append(failures, err)
		}
	}

	if left := counts[gigahostRowUnknownAccount] + counts[gigahostRowOtherAccount] + counts[gigahostRowUnmeasured]; left > 0 {
		// Observable without naming an account or a credential: why rows were
		// left alone, and how many.
		slog.Info("Provider inventory left server existence state unchanged for rows it cannot speak for",
			"unknown_account_rows", counts[gigahostRowUnknownAccount],
			"other_account_rows", counts[gigahostRowOtherAccount],
			"unmeasured_rows", counts[gigahostRowUnmeasured])
	}
	if filtered := counts[gigahostRowScopeEvidence]; filtered > 0 {
		// The key's visibility is narrower than the account: these servers exist but
		// the listing did not enumerate them, so the listing is not evidence.
		slog.Info("Provider inventory did not enumerate servers that still exist; no absence was recorded for them",
			"rows", filtered)
	}
	return errors.Join(failures...)
}

// writeProviderAbsence stores one row's observation when it differs from the stored
// one.
func (h *Handlers) writeProviderAbsence(ctx context.Context, row providerBackedServer, present bool, now time.Time) error {
	if present == (row.absentAt == "") {
		// The row already states what the provider says; nothing to write.
		return nil
	}
	absentAt := now
	if present {
		absentAt = time.Time{}
	}
	if err := h.db.SetServerProviderAbsence(ctx, row.serverID, absentAt); err != nil {
		return fmt.Errorf("server %d: %w", row.serverID, err)
	}
	slog.Info("Provider inventory changed a server's existence state",
		"server_id", row.serverID,
		"provider_server_id", row.providerServerID,
		"provider_absent", !present)
	return nil
}
