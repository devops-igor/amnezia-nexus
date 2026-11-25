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
//   - a per-server read is used only to add presence: an answer carrying the server
//     clears a mark. A "not found", a refusal, an error or an unrecognized shape is
//     inconclusive and changes nothing;
//   - absence is concluded only from an inventory answer certified as the account's
//     whole enumeration, which the account summary's service counts establish (see
//     gigahostInventoryCertified). Without that certification nothing is marked
//     absent, and every row keeps the state it had.
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
	// accountServers is the account-wide server count this pass read from the summary,
	// and listingCredible reports whether this pass's own evidence is consistent: the
	// listing's size equals that count. Only a credible pass contributes evidence, and a
	// row needs two consecutive credible passes to be recorded absent.
	accountServers  int
	listingCredible bool
}

// gigahostServerReported reports whether the provider answered with this server.
//
// That is the only thing a detail read is used for. Every other outcome - a 404, a
// refusal, an unauthenticated or malformed answer, a timeout - is not evidence in
// either direction and therefore decides nothing here. In particular, this panel does
// not model what a "not found" status means for a provider whose key may be limited
// to some servers: absence is decided by the inventory answer alone (see
// gigahostInventoryCertified).
func gigahostServerReported(ctx context.Context, client gigahost.Client, serverID int64) bool {
	if client == nil || serverID <= 0 {
		return false
	}
	_, err := client.GetServer(ctx, serverID)
	return err == nil
}

// absenceCandidate is the evidence one pass records so the next one can confirm it.
//
// It carries the account the omission belongs to and the two counts that made the pass
// credible, so a confirmation compares like with like. It is in memory on purpose: the
// rule is about consecutive reconciliation passes in this process, a restart simply
// requires two fresh passes, and no stale snapshot is ever trusted.
type absenceCandidate struct {
	accountID        string
	providerServerID int64
	listedCount      int
	accountServers   int
	seenAt           time.Time
}

// gigahostAccountServerCount reads the account-wide server count the summary reports.
//
// GET /dashboard is documented as available "to every valid token and API key,
// regardless of its permissions", and its services figures count the account's own
// servers. It is the only documented account-wide count the panel can read with the
// credential it holds.
func (h *Handlers) gigahostAccountServerCount(ctx context.Context, client gigahost.Client) (int, bool) {
	dashboard, err := client.GetDashboard(ctx)
	switch {
	case err != nil:
		slog.Warn("Provider account summary unavailable; absence not recorded in this pass", "err", err)
		return 0, false
	case dashboard == nil || !dashboard.ServicesPresent:
		slog.Warn("Provider account summary carried no service counts; absence not recorded in this pass")
		return 0, false
	}
	return dashboard.Services.ServerCount(), true
}

// confirmRepeatedOmissions turns a repeated omission into a confirmed absence.
//
// Absence is concluded only on evidence that repeats: the row must be omitted in two
// consecutive passes, and each of those passes must be credible on its own - its own
// listing's size equal to its own account-wide count. Anything else clears the carried
// evidence: a mismatch, a missing count, an unreadable summary, or a pass in which the
// row was listed or reported. Two consecutive agreements are what a single coincidental
// equality cannot produce.
func (h *Handlers) confirmRepeatedOmissions(accountID string, listedCount, accountServers int, credible bool, candidates []int64) map[int64]struct{} {
	h.absenceMu.Lock()
	defer h.absenceMu.Unlock()

	confirmed := make(map[int64]struct{}, len(candidates))
	next := make(map[int64]absenceCandidate, len(candidates))
	if credible {
		for _, id := range candidates {
			if previous, ok := h.absenceCandidates[id]; ok &&
				previous.accountID == accountID &&
				previous.listedCount == listedCount &&
				previous.accountServers == accountServers {
				confirmed[id] = struct{}{}
				continue
			}
			next[id] = absenceCandidate{
				accountID:        accountID,
				providerServerID: id,
				listedCount:      listedCount,
				accountServers:   accountServers,
				seenAt:           time.Now().UTC(),
			}
		}
	}
	h.absenceCandidates = next
	if len(confirmed) == 0 && len(candidates) > 0 && !credible {
		slog.Info("Provider inventory was not credible in this pass; carried absence evidence cleared",
			"unlisted_rows", len(candidates), "listed_servers", listedCount, "account_servers", accountServers)
	}
	return confirmed
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

	// Credibility is a property of this pass's own evidence: its listing's size against
	// the account-wide count read in the same pass. A missing or unreadable summary makes
	// the pass incredible, which clears the carried evidence rather than concluding
	// anything from it.
	accountServers, counted := h.gigahostAccountServerCount(callCtx, client)
	return gigahostInventoryAnswer{
		listed:          listed,
		accountID:       accountID,
		client:          client,
		accountServers:  accountServers,
		listingCredible: counted && len(listed) == accountServers,
	}, nil
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
	// gigahostRowListed: the inventory lists it.
	gigahostRowListed
	// gigahostRowDetailPresent: the inventory did not list it but the detail read
	// returned it, so it exists.
	gigahostRowDetailPresent
	// gigahostRowUnlisted: the inventory did not list it and no detail read returned
	// it. Only a certified-complete inventory answer may turn this into absence.
	gigahostRowUnlisted
)

// presence reports whether the row exists, and whether the pass has an existence
// answer at all.
func (d gigahostRowDecision) presence() (present, measured bool) {
	switch d {
	case gigahostRowListed, gigahostRowDetailPresent:
		return true, true
	case gigahostRowUnlisted:
		return false, true
	default:
		return false, false
	}
}

// decideGigahostRow applies the rule for one row against one answer: only a row of
// the answering account is judged, and a detail read is used only to add presence.
func decideGigahostRow(ctx context.Context, row providerBackedServer, answer gigahostInventoryAnswer) gigahostRowDecision {
	if row.accountID == "" {
		return gigahostRowUnknownAccount
	}
	if row.accountID != answer.accountID {
		return gigahostRowOtherAccount
	}
	if _, listed := answer.listed[row.providerServerID]; listed {
		return gigahostRowListed
	}
	if gigahostServerReported(ctx, answer.client, row.providerServerID) {
		return gigahostRowDetailPresent
	}
	return gigahostRowUnlisted
}

// gigahostPassOutcome is what one pass concluded, row by row.
type gigahostPassOutcome struct {
	decisions []gigahostRowDecision
	counts    map[gigahostRowDecision]int
}

// decideGigahostRows judges every row against one answer.
func decideGigahostRows(ctx context.Context, rows []providerBackedServer, answer gigahostInventoryAnswer) gigahostPassOutcome {
	outcome := gigahostPassOutcome{
		decisions: make([]gigahostRowDecision, len(rows)),
		counts:    make(map[gigahostRowDecision]int, len(rows)),
	}
	for i, row := range rows {
		outcome.decisions[i] = decideGigahostRow(ctx, row, answer)
		outcome.counts[outcome.decisions[i]]++
	}
	return outcome
}

// unlistedProviderIDs returns the provider server ids of the rows this pass saw omitted,
// which are the only rows that may become an absence candidate. Presence was already
// decided per row, so a server a detail read returned is not among them.
func unlistedProviderIDs(rows []providerBackedServer, decisions []gigahostRowDecision) []int64 {
	ids := make([]int64, 0, len(rows))
	for i, row := range rows {
		if decisions[i] == gigahostRowUnlisted {
			ids = append(ids, row.providerServerID)
		}
	}
	return ids
}

// applyGigahostInventoryPresence writes the provider's answer onto the rows whose
// state it changes. A row already carrying the answer is not rewritten, so the
// original observation time survives a repeated pass.
//
// Absence has exactly one source: an omission that repeats across two consecutive
// credible passes (see confirmRepeatedOmissions). A single pass - however consistent its
// own counts look - can never record it. A detail read is never an absence observation;
// it can only add presence, which clears a mark immediately.
func (h *Handlers) applyGigahostInventoryPresence(
	ctx context.Context, rows []providerBackedServer, answer gigahostInventoryAnswer,
) error {
	now := time.Now().UTC()
	outcome := decideGigahostRows(ctx, rows, answer)

	candidates := unlistedProviderIDs(rows, outcome.decisions)
	confirmed := h.confirmRepeatedOmissions(answer.accountID, len(answer.listed), answer.accountServers, answer.listingCredible, candidates)
	if len(candidates) > 0 && len(confirmed) == 0 {
		// Every candidate keeps the state it had: this pass either was not credible or is
		// the first of the two that must agree.
		slog.Info("Provider inventory recorded no absence in this pass",
			"unlisted_rows", len(candidates),
			"listing_credible", answer.listingCredible,
			"listed_servers", len(answer.listed),
			"account_servers", answer.accountServers)
	}

	failures := h.writeDecidedRows(ctx, rows, outcome.decisions, confirmed, now)
	if left := outcome.counts[gigahostRowUnknownAccount] + outcome.counts[gigahostRowOtherAccount]; left > 0 {
		// Observable without naming an account or a credential: why rows were
		// left alone, and how many.
		slog.Info("Provider inventory left server existence state unchanged for rows it cannot speak for",
			"unknown_account_rows", outcome.counts[gigahostRowUnknownAccount],
			"other_account_rows", outcome.counts[gigahostRowOtherAccount])
	}
	return errors.Join(failures...)
}

// writeDecidedRows stores the decisions that hold an existence answer.
//
// The only write that can hide a server is the absence write, and it is gated by the
// confirmation a repeated omission produced: without it, an omitted row keeps whatever
// state it had.
func (h *Handlers) writeDecidedRows(
	ctx context.Context, rows []providerBackedServer, decisions []gigahostRowDecision, confirmed map[int64]struct{}, now time.Time,
) []error {
	var failures []error
	for i, row := range rows {
		present, measured := decisions[i].presence()
		if !measured {
			continue
		}
		if !present {
			if _, ok := confirmed[row.providerServerID]; !ok {
				// Absence may only come from an omission confirmed by two agreeing passes.
				continue
			}
		}
		if err := h.writeProviderAbsence(ctx, row, present, now); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
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
