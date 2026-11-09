package main

// Opt-in, read-only provider evidence for the recovery proposal.
//
// The default run of this command is deliberately offline: it reads one local
// ledger and reports what it can prove from that alone, which is nothing
// conclusive. A proposal that can never justify a release is not useful to an
// operator, so this file adds the one thing that CAN justify one - an actual
// read of the provider's own view.
//
// The rules it follows, and why:
//
//   - It is opt-in. Nothing here runs unless --provider-read was given, so a
//     plain inspection never touches the network.
//   - It is read-only. Only GET reads are used: the catalog, the server
//     inventory and a deployment status. No order, cancellation or delete call
//     is reachable from this command, so it cannot buy or destroy anything.
//   - It is bounded. One inventory read, one catalog read and at most
//     --max-order-lookups deployment-status reads, all under one context with
//     an explicit timeout, and the same per-run lookup bound the purchase path
//     applies to itself.
//   - It never queries a locally invented order id. A synthetic identifier
//     names nothing at the provider, so its answer would mean nothing.
//   - Every observation is bound to the exact ledger row that was read, and the
//     whole pass is bound to one ledger fingerprint. A later apply step can
//     therefore refuse evidence that no longer describes the record or the
//     ledger it was collected from.
//
// The credential comes from the environment (preferred) or a flag. It is never
// printed and never appears in the report.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostevidence"
)

// defaultProviderTimeout bounds one provider-read pass end to end.
const defaultProviderTimeout = 30 * time.Second

// defaultOrderLookups mirrors the panel's own per-attempt bound, so an operator
// run cannot query the provider harder than a purchase attempt would.
const defaultOrderLookups = 10

// providerConfig is the opt-in provider read.
type providerConfig struct {
	enabled    bool
	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxLookups int
}

// resolveAPIKey prefers the environment over the flag value, because a flag is
// visible in the process list on a shared host.
func resolveAPIKey(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("GIGAHOST_API_KEY"))
}

// newClient builds the read-only provider client for one run.
//
// A missing or malformed credential is an error rather than a silent fallback:
// an operator who asked for provider evidence must not receive an offline report
// that looks like a provider answer.
func (p providerConfig) newClient() (gigahost.Client, error) {
	if !p.enabled {
		return nil, nil
	}
	if p.apiKey == "" {
		return nil, errors.New("--provider-read needs a credential: set GIGAHOST_API_KEY or pass --api-key")
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = defaultProviderTimeout
	}
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: p.baseURL,
		APIKey:  p.apiKey,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("provider client: %w", err)
	}
	return client, nil
}

// providerEvidence is what one provider-read pass produced, plus what a later
// apply needs in order to refuse stale evidence.
type providerEvidence struct {
	// Plans is the provider catalog, used to price legacy reservations with the
	// same resolver the purchase path uses.
	Plans []gigahostbudget.Plan
	// Servers is the provider inventory in shared terms.
	Servers []gigahostbudget.Server
	// Evidence is the per-record observation handed to the shared calculation.
	Evidence map[int64]gigahostbudget.Evidence
	// Bindings binds each observation to the ledger state it was made against.
	Bindings evidenceBindings
	// OrderLookups counts deployment-status reads actually issued.
	OrderLookups int
	// Warnings records what could not be read, without turning it into absence.
	Warnings []string
}

// evidenceBindings is the stale-safe anchor for a later apply.
//
// It records one fingerprint per observed row and one for the whole ledger.
// Applying evidence that does not match the current row and ledger is refused,
// which is what makes a read-only proposal safe to hand to a later write step.
type evidenceBindings struct {
	// Ledger is the fingerprint of the ledger as it was read for this pass.
	Ledger ledgerFingerprint
	// Rows maps a record id to the fingerprint of the exact row observed.
	Rows map[int64]string
}

// ledgerFingerprint identifies the ledger a pass was collected against.
type ledgerFingerprint struct {
	ObservedAt string
	Rows       int64
	MaxID      int64
	Released   int64
	Digest     string
	Complete   bool
}

// collectProviderEvidence reads the provider read-only and returns the shared
// per-record observations.
//
// An inventory read that fails stops the pass: without it the collector cannot
// tell a matching server from an absent one, and reporting that as "no
// evidence" would look like a provider answer when it is a provider outage. The
// caller reports the failure and proposes nothing.
func collectProviderEvidence(
	ctx context.Context, client gigahost.Client, dbPath string, orders []models.GigahostOrder, p providerConfig,
) (*providerEvidence, error) {
	if client == nil {
		return nil, errors.New("no provider client")
	}
	servers, err := client.GetServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("read provider inventory: %w", err)
	}

	pe := &providerEvidence{Warnings: nil}
	catalog, catErr := client.GetCatalog(ctx)
	if catErr != nil {
		// Pricing can survive without the catalog: a record that carries its
		// order-time contract is fully priced, and one that does not is reported
		// as an unidentifiable price (a lower bound) rather than being guessed.
		pe.Warnings = append(pe.Warnings,
			"provider catalog could not be read, so only reservations with a persisted price contract are priced exactly: "+catErr.Error())
	}
	pe.Plans = gigahostevidence.Plans(catalog)
	pe.Servers = gigahostevidence.Servers(servers)

	limits := gigahostevidence.Limits{MaxOrderLookups: p.maxLookups}
	collected := gigahostevidence.Collect(ctx, client, servers, orders, limits)
	pe.OrderLookups = collected.OrderLookups

	pe.Evidence = make(map[int64]gigahostbudget.Evidence, len(collected.Observations))
	pe.Bindings = evidenceBindings{
		Ledger: ledgerFingerprintOf(ctx, dbPath),
		Rows:   make(map[int64]string, len(collected.Observations)),
	}
	omitted, failed := 0, 0
	for id, obs := range collected.Observations {
		pe.Evidence[id] = obs.Evidence
		pe.Bindings.Rows[id] = rowFingerprint(obs.Expect)
		if obs.Evidence.OrderOmittedFromDeployStatus {
			omitted++
		}
		if obs.Evidence.OrderQueryFailed {
			failed++
		}
	}
	pe.Warnings = append(pe.Warnings, providerReadWarnings(len(collected.Observations), omitted, failed, pe.OrderLookups)...)
	return pe, nil
}

// providerReadWarnings states what the pass did NOT establish, so an operator
// cannot read a quiet report as a clean bill of health.
func providerReadWarnings(observed, omitted, failed, lookups int) []string {
	out := []string{fmt.Sprintf(
		"provider run: %d record(s) observed with %d deployment-status read(s); this is a read-only pass and wrote nothing",
		observed, lookups)}
	if omitted > 0 {
		out = append(out, fmt.Sprintf(
			"%d order(s) were omitted from the provider's deployment status list; the contract also omits canceled orders and servers that were deleted, so an omission is not proof of anything",
			omitted))
	}
	if failed > 0 {
		out = append(out, fmt.Sprintf(
			"%d order lookup(s) failed or timed out; a failed read is not evidence of absence", failed))
	}
	return out
}

// ledgerFingerprintOf summarizes the ledger read for this pass. It reuses the
// snapshot reader, which also works on the older schema.
func ledgerFingerprintOf(ctx context.Context, dbPath string) ledgerFingerprint {
	fp := ledgerFingerprint{ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	state, err := database.ReadLedgerState(ctx, dbPath)
	if err != nil {
		fp.Digest = "unavailable: " + err.Error()
		return fp
	}
	fp.Rows = state.Orders.Rows
	fp.MaxID = state.Orders.MaxID
	fp.Released = state.Orders.Released
	fp.Digest = state.Orders.Digest
	fp.Complete = state.Orders.Present
	return fp
}

// rowFingerprint is a stable digest of one observed ledger row's identity and
// accounting fields. It is what a later apply compares, so a row that changed
// after the observation cannot be released on the strength of it.
func rowFingerprint(o models.GigahostOrder) string {
	var b strings.Builder
	for _, v := range []string{
		strconv.FormatInt(o.ID, 10),
		o.OrderID,
		strconv.FormatInt(o.ServerID, 10),
		o.Status,
		strconv.Itoa(o.PlanID),
		strconv.Itoa(o.RegionID),
		strconv.FormatFloat(o.HourlyPriceNOK, 'f', -1, 64),
		strconv.Itoa(o.PriceID),
		strconv.FormatFloat(o.MonthlyCapNOK, 'f', -1, 64),
		o.Currency,
		o.AssignedIP,
		o.ReleasedAt,
		o.ReleaseReason,
		o.CreatedAt.UTC().Format(time.RFC3339Nano),
		o.UpdatedAt.UTC().Format(time.RFC3339Nano),
	} {
		b.WriteString(v)
		b.WriteByte(0x1f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
