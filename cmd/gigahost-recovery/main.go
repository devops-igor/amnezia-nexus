// Command gigahost-recovery reconciles the Gigahost reservation ledger of one
// panel database.
//
// It is the operator-facing half of the same calculation the panel uses: it
// loads the ledger, prices every reservation exactly as the purchase path does,
// and prints what would change. By default it does NOT write anything.
//
// Safety model:
//
//   - Read-only by default. A run without --apply only reports.
//   - Offline by default too. A run without --provider-read reads nothing but
//     the local database, so it holds NO authoritative proof and releases
//     NOTHING. There is deliberately no operator waiver: the approved scope
//     forbids an administrator acknowledgement standing in for authoritative
//     reconciliation, and a free-text note is not proof of anything.
//   - --provider-read is the opt-in evidence path. It performs read-only GETs
//     (catalog, server inventory, deployment status) through the same client and
//     the same collector as the purchase path, bounded by an explicit timeout
//     and a per-run lookup limit. It cannot order, cancel or delete anything.
//     The only observation that can justify a release is a provider-reported
//     matching server that is terminated or deleted, which ends the recurring
//     commitment.
//   - Anything else stays counted and is named with the exact proof it needs. An
//     omission from the provider's deployment status list is not proof of
//     absence, a failed or timed-out read is not proof of absence, a locally
//     generated order id is never queried at all, and a waitlist reservation is
//     an armed commitment that must keep counting.
//   - --apply ALWAYS takes a coherent SQLite snapshot first (VACUUM INTO inside
//     one read transaction, one self-contained file, mode 0600) and verifies it:
//     SQLite integrity_check, the schema inventory, per-table row counts, and the
//     Gigahost ledger history it must still contain. There is no way to skip it;
//     --no-backup is refused rather than honored. An existing destination is
//     never overwritten, and the destination may not be the database, one of its
//     sidecar files, a symlink or a hardlink to it. If the snapshot cannot be
//     taken or verified, the run stops before opening the database read-write.
//   - --restore-to writes a verified copy of a snapshot into a brand-new path, so
//     an operator can inspect a restored database before swapping it in. It never
//     writes to the source and never replaces an existing file.
//   - Releasing writes a marker plus an audit row and keeps the original status,
//     so a repeated run reports "already released" and changes nothing.
//   - Nothing here can order, cancel or delete a VPS.
//
// Usage:
//
//	gigahost-recovery --db /path/panel.db                     # dry run (default, offline, read-only)
//	gigahost-recovery --db /path/panel.db --provider-read     # read-only provider evidence, still a proposal
//	gigahost-recovery --db /path/panel.db --json              # machine-readable report
//	gigahost-recovery --db /path/panel.backup.db --restore-to /path/restored.db
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostevidence"
)

// exit codes, so a script can distinguish the outcomes.
const (
	exitOK         = 0
	exitFailure    = 1
	exitUsage      = 2
	exitUnresolved = 3
)

// config is one invocation.
type config struct {
	dbPath      string
	budgetNOK   float64
	apply       bool
	asJSON      bool
	jsonOutPath string
	backupPath  string
	noBackup    bool
	restoreTo   string
	catalogPath string
	showHelp    bool
	provider    providerConfig
}

// report is what one run found and did.
type report struct {
	Database        string                          `json:"database"`
	Mode            string                          `json:"mode"`
	BackupPath      string                          `json:"backup_path,omitempty"`
	Backup          *database.SnapshotReceipt       `json:"backup,omitempty"`
	RestoredTo      string                          `json:"restored_to,omitempty"`
	Restore         *database.SnapshotReceipt       `json:"restore,omitempty"`
	CapNOK          float64                         `json:"cap_nok"`
	CommittedBefore float64                         `json:"committed_before_nok"`
	CommittedAfter  float64                         `json:"committed_after_nok"`
	Released        []gigahostbudget.ProposedChange `json:"released"`
	Retained        []gigahostbudget.ProposedChange `json:"retained"`
	Unresolved      []gigahostbudget.ProposedChange `json:"unresolved"`
	AlreadyReleased int                             `json:"already_released"`
	IncompleteTotal bool                            `json:"incomplete_total"`
	// EvidenceSource names what the proposal's conclusions rest on:
	// "offline" (ledger only, never conclusive) or "provider_read".
	EvidenceSource string `json:"evidence_source"`
	// OrderLookups is how many provider deployment-status reads were issued.
	OrderLookups int `json:"order_lookups"`
	// Bindings is the stale-safe anchor a later apply must match. It is only
	// present when a provider read actually happened.
	Bindings *evidenceBindings `json:"bindings,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	// ApplyErrors are failures of a write. They are separate from Warnings
	// because a failed write must fail the run, not merely annotate it.
	ApplyErrors []string `json:"apply_errors,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, ok := parseConfig(args, stderr)
	if !ok {
		return exitUsage
	}
	if cfg.showHelp {
		return exitOK
	}
	if err := checkInvocation(cfg, stderr); err != nil {
		fmt.Fprintf(stderr, "gigahost-recovery: %v\n", err)
		return exitUsage
	}

	rep, unresolvedCount, err := execute(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gigahost-recovery: %v\n", err)
		return exitFailure
	}

	if err := emit(stdout, cfg, rep); err != nil {
		fmt.Fprintf(stderr, "gigahost-recovery: writing report: %v\n", err)
		return exitFailure
	}
	return exitCodeFor(cfg, rep, unresolvedCount)
}

// parseConfig reads the flags. ok is false when the flags themselves did not
// parse, which is a usage error reported by the flag package already.
func parseConfig(args []string, stderr io.Writer) (cfg config, ok bool) {
	fs := flag.NewFlagSet("gigahost-recovery", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.dbPath, "db", "", "path to the panel SQLite database (required)")
	fs.Float64Var(&cfg.budgetNOK, "budget", 0, "monthly budget cap in NOK as configured in the panel; 0 means no cap")
	fs.BoolVar(&cfg.apply, "apply", false, "write the proposed releases (default is a read-only dry run)")
	fs.BoolVar(&cfg.asJSON, "json", false, "emit the plan as JSON instead of text")
	fs.StringVar(&cfg.jsonOutPath, "out", "", "write the JSON plan to this path as well")
	fs.StringVar(&cfg.backupPath, "backup", "", "snapshot path for --apply (default: <db>.gigahost-backup-<timestamp>); an existing file is never overwritten")
	fs.BoolVar(&cfg.noBackup, "no-backup", false, "refused: --apply always takes a verified snapshot before writing")
	fs.StringVar(&cfg.restoreTo, "restore-to", "", "restore the --db snapshot into this NEW path (never overwrites anything)")
	fs.StringVar(&cfg.catalogPath, "catalog", "", "JSON file of catalog rows, for pricing legacy records offline (never fetched)")
	fs.BoolVar(&cfg.provider.enabled, "provider-read", false, "read the provider read-only to obtain authoritative evidence (opt-in; default is a local, offline report)")
	fs.StringVar(&cfg.provider.apiKey, "api-key", "", "provider credential for --provider-read (prefer the GIGAHOST_API_KEY environment variable)")
	fs.StringVar(&cfg.provider.baseURL, "provider-url", "", "provider API base URL for --provider-read (default: the provider's own)")
	fs.DurationVar(&cfg.provider.timeout, "provider-timeout", defaultProviderTimeout, "overall timeout for one --provider-read pass")
	fs.IntVar(&cfg.provider.maxLookups, "max-order-lookups", defaultOrderLookups, "maximum deployment-status reads one --provider-read pass may issue")
	fs.BoolVar(&cfg.showHelp, "help", false, "show this help")
	if err := fs.Parse(args); err != nil {
		return cfg, false
	}
	if cfg.showHelp {
		fs.Usage()
		return cfg, true
	}
	cfg.provider.apiKey = resolveAPIKey(cfg.provider.apiKey)
	return cfg, true
}

// checkInvocation rejects an invocation the tool cannot serve as asked, before
// anything is read or written.
func checkInvocation(cfg config, stderr io.Writer) error {
	if cfg.dbPath == "" {
		fmt.Fprintln(stderr, "gigahost-recovery: --db is required")
		return errAlreadyReported
	}
	if _, err := os.Stat(cfg.dbPath); err != nil {
		return fmt.Errorf("cannot read database %s: %w", cfg.dbPath, err)
	}
	return validateConfig(cfg)
}

// errAlreadyReported marks a usage error whose message was already printed.
var errAlreadyReported = errors.New("usage")

// exitCodeFor maps a completed run onto its exit code. The mapping is the tool's
// contract with scripts, so it is one named function rather than trailing ifs.
func exitCodeFor(cfg config, rep report, unresolvedCount int) int {
	switch {
	case len(rep.ApplyErrors) > 0:
		return exitFailure
	case unresolvedCount > 0 && !cfg.apply:
		return exitUnresolved
	default:
		return exitOK
	}
}

// validateConfig rejects combinations that cannot be honored. Refusing an
// unhonourable flag is better than accepting it and doing something weaker.
func validateConfig(cfg config) error {
	if cfg.apply && cfg.noBackup {
		return errors.New("--no-backup is not supported: --apply always takes a verified snapshot first")
	}
	if err := validateRestoreConfig(cfg); err != nil {
		return err
	}
	if cfg.provider.enabled && cfg.provider.maxLookups <= 0 {
		return errors.New("--provider-read with --max-order-lookups <= 0 would disable order lookups entirely; omit --provider-read for an offline report")
	}
	if cfg.apply && cfg.provider.enabled {
		// Applying provider evidence needs the stale-safe write path (re-check the
		// observed row inside the release transaction). This checkpoint delivers
		// the read-only proposal and its bindings; applying it is the next step,
		// so the combination is refused rather than silently written unbound.
		return errors.New("--apply with --provider-read is not supported yet: review the proposal, then apply it with the fresh-evidence write path (the read-only report and its bindings are kept for that step)")
	}
	return nil
}

// validateRestoreConfig rejects the flag combinations a snapshot restore cannot
// honor: a restore is a file copy, not a financial decision.
func validateRestoreConfig(cfg config) error {
	if cfg.restoreTo == "" {
		return nil
	}
	if cfg.apply {
		return errors.New("--restore-to and --apply are separate operations; restore into a new file first, then inspect it")
	}
	if cfg.noBackup || cfg.backupPath != "" {
		return errors.New("--restore-to does not take a snapshot destination; it writes only to --restore-to")
	}
	if cfg.provider.enabled {
		return errors.New("--restore-to copies a file and takes no provider evidence; drop --provider-read")
	}
	return nil
}

// execute dispatches between restoring a snapshot and planning/applying releases.
func execute(cfg config) (report, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if cfg.restoreTo != "" {
		return executeRestore(ctx, cfg)
	}
	return executePlan(ctx, cfg)
}

// executeRestore copies a verified snapshot to a new database file, so an
// operator can inspect the restored data before replacing anything by hand.
func executeRestore(ctx context.Context, cfg config) (report, int, error) {
	rep := report{Database: cfg.dbPath, Mode: "restored"}
	receipt, err := database.RestoreSnapshot(ctx, cfg.dbPath, cfg.restoreTo)
	if err != nil {
		return rep, 0, err
	}
	rep.RestoredTo = cfg.restoreTo
	rep.Restore = receipt
	return rep, 0, nil
}

// executePlan opens the database read-write only when applying, computes the
// plan, and applies it when asked.
func executePlan(ctx context.Context, cfg config) (report, int, error) {
	rep := report{
		Database:       cfg.dbPath,
		Mode:           "dry-run",
		CapNOK:         cfg.budgetNOK,
		EvidenceSource: "offline",
	}

	// A dry run opens the database strictly read-only and never migrates: an
	// inspection must not change the file it inspects. --apply takes the
	// coherent snapshot BEFORE opening read-write, so the snapshot captures the
	// state before any migration or release, not a partly-changed file, and a
	// snapshot that cannot be taken or verified stops the run here.
	if cfg.apply {
		receipt, err := takeMandatorySnapshot(ctx, cfg)
		if err != nil {
			return rep, 0, err
		}
		rep.BackupPath = receipt.Path
		rep.Backup = receipt
	}
	db, err := openLedgerDB(cfg)
	if err != nil {
		return rep, 0, err
	}
	defer func() { _ = db.Close() }()

	orders, err := readLedgerOrders(ctx, db, cfg.apply)
	if err != nil {
		return rep, 0, err
	}
	plans, err := loadPlans(cfg.catalogPath)
	if err != nil {
		return rep, 0, err
	}

	evidence, err := collectEvidence(ctx, cfg, &rep, orders, &plans)
	if err != nil {
		return rep, 0, err
	}

	entries := prepareEntries(orders)
	proposal, err := gigahostbudget.Propose(gigahostbudget.Input{
		CapNOK:   cfg.budgetNOK,
		Plans:    plans,
		Entries:  entries,
		Evidence: evidence,
	})
	if err != nil {
		// A dry run must still be useful: report the unpriceable state instead
		// of aborting with nothing.
		rep.Warnings = append(rep.Warnings, "the committed total could not be computed: "+err.Error())
		return rep, 0, nil
	}

	fillPlanReport(&rep, proposal, orders)
	if !cfg.apply {
		return rep, len(rep.Unresolved), nil
	}
	rep.Mode = "applied"
	applyProposedReleases(ctx, db, proposal.Changes, &rep)
	return rep, len(rep.Unresolved), nil
}

// collectEvidence produces the observation map the shared calculation needs.
//
// An offline run supplies none, and says so: every evidence field of the zero
// value means "nothing observed", which is never conclusive, so an offline
// report proposes nothing and names what a human must verify. A provider run
// supplies real observations and the bindings a later apply must match.
func collectEvidence(
	ctx context.Context, cfg config, rep *report, orders []models.GigahostOrder, plans *[]gigahostbudget.Plan,
) (map[int64]gigahostbudget.Evidence, error) {
	if !cfg.provider.enabled {
		rep.Warnings = append(rep.Warnings,
			"offline run: no provider evidence is available, so no release is proposed; unresolved reservations are kept and named")
		return nil, nil
	}

	client, err := cfg.provider.newClient()
	if err != nil {
		return nil, err
	}
	pe, err := collectProviderEvidence(ctx, client, cfg.dbPath, orders, cfg.provider)
	if err != nil {
		// A failed provider pass is reported as a failure, not as "no evidence":
		// the operator asked for provider proof and did not get it.
		return nil, err
	}
	rep.EvidenceSource = "provider_read"
	rep.OrderLookups = pe.OrderLookups
	rep.Bindings = &pe.Bindings
	rep.Warnings = append(rep.Warnings, pe.Warnings...)
	if len(pe.Plans) > 0 {
		// The provider catalog is authoritative for pricing, so it outranks an
		// operator-supplied offline export when both are present.
		*plans = pe.Plans
	}
	return pe.Evidence, nil
}

// openLedgerDB opens the database read-only for a dry run and read-write (which
// also applies pending migrations) for --apply.
func openLedgerDB(cfg config) (*database.DB, error) {
	opens := database.OpenReadOnly
	if cfg.apply {
		opens = func(path string) (*database.DB, error) { return database.Open(path, "") }
	}
	db, err := opens(cfg.dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return db, nil
}

// readLedgerOrders reads the ledger with the reader that matches the open mode: a
// dry run tolerates the older schema and never upgrades it.
func readLedgerOrders(ctx context.Context, db *database.DB, apply bool) ([]models.GigahostOrder, error) {
	var (
		orders []models.GigahostOrder
		err    error
	)
	if apply {
		orders, err = db.ListGigahostOrders(ctx)
	} else {
		orders, err = db.ListGigahostOrdersReadOnly(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("read ledger: %w", err)
	}
	return orders, nil
}

// fillPlanReport copies the shared proposal into the operator report. Empty lists
// are emitted as empty arrays so a machine reader cannot confuse "empty" with
// "not reported".
func fillPlanReport(rep *report, proposal gigahostbudget.Proposal, orders []models.GigahostOrder) {
	rep.CommittedBefore = proposal.CommittedBefore
	rep.CommittedAfter = proposal.CommittedAfter
	rep.IncompleteTotal = proposal.IncompleteTotal
	rep.Released = append([]gigahostbudget.ProposedChange{}, proposal.Changes...)
	rep.Retained = append([]gigahostbudget.ProposedChange{}, proposal.Retained...)
	rep.Unresolved = []gigahostbudget.ProposedChange{}
	for _, r := range proposal.Retained {
		if r.State == gigahostbudget.StateUnresolved {
			rep.Unresolved = append(rep.Unresolved, r)
		}
	}
	for _, o := range orders {
		if o.ReleasedAt != "" {
			rep.AlreadyReleased++
		}
	}
}

// applyProposedReleases writes each justified release and records the ones it
// refused, so a partial run is reported rather than silently half-applied.
func applyProposedReleases(ctx context.Context, db *database.DB, changes []gigahostbudget.ProposedChange, rep *report) {
	for _, change := range changes {
		reason := reasonFor(change)
		if reason == "" {
			rep.ApplyErrors = append(rep.ApplyErrors,
				fmt.Sprintf("record %d: no conclusive evidence, refusing to release", change.RecordID))
			continue
		}
		err := db.ReleaseGigahostOrder(ctx, change.RecordID, reason, change.Explanation)
		if err == nil || errors.Is(err, database.ErrGigahostOrderAlreadyReleased) {
			continue
		}
		rep.ApplyErrors = append(rep.ApplyErrors, fmt.Sprintf("record %d: %v", change.RecordID, err))
	}
}

// prepareEntries builds the shared input from the ledger.
//
// It supplies no release evidence, and that is the point: this function is the
// offline path, so any evidence it could hand over would be an operator
// assertion rather than provider fact. A note-only waiver was explicitly
// rejected by the approved scope. Provider observations are supplied separately
// by collectEvidence.
func prepareEntries(orders []models.GigahostOrder) []gigahostbudget.Entry {
	return gigahostevidence.Entries(orders)
}

// reasonFor returns the audit reason for one proposed change, or "" when the
// evidence does not justify it.
//
// The proposal already only contains changes the shared classification called
// releasable, and it records which reason justified each one. The operator
// confirmation is checked again here so a confirmation that was consumed by the
// proposal cannot be replayed onto a different record.
func reasonFor(change gigahostbudget.ProposedChange) string {
	if change.Action != gigahostbudget.ActionRelease || change.Reason == "" {
		return ""
	}
	if change.Reason == "operator_confirmed_no_charge" && change.Evidence == "" {
		return ""
	}
	return change.Reason
}

// loadPlans reads an optional offline catalog export. It never fetches the
// catalog: this tool must not depend on provider connectivity or credentials.
func loadPlans(path string) ([]gigahostbudget.Plan, error) {
	if path == "" {
		return nil, nil
	}
	// The path is an operator-supplied local file on their own machine, which is
	// the entire interface of this command; it is not derived from network input.
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}
	var rows []struct {
		ProductID      int     `json:"product_id"`
		PriceID        int     `json:"price_id"`
		Currency       string  `json:"currency"`
		HourlyRateNOK  float64 `json:"hourly_rate_nok"`
		MonthlyCeiling float64 `json:"monthly_ceiling_nok"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("parse catalog file: %w", err)
	}
	plans := make([]gigahostbudget.Plan, 0, len(rows))
	for _, r := range rows {
		plans = append(plans, gigahostbudget.Plan{
			ProductID:      r.ProductID,
			PriceID:        r.PriceID,
			Currency:       r.Currency,
			HourlyRateNOK:  r.HourlyRateNOK,
			MonthlyCeiling: r.MonthlyCeiling,
		})
	}
	return plans, nil
}

// takeMandatorySnapshot writes and verifies the coherent pre-write snapshot.
//
// It is mandatory: there is no flag that skips it, because a recovery write
// without a restorable copy of the pre-change state has no undo. The default
// destination is unique, and an existing destination is refused rather than
// overwritten, so an earlier pre-change copy is never destroyed.
func takeMandatorySnapshot(ctx context.Context, cfg config) (*database.SnapshotReceipt, error) {
	path := cfg.backupPath
	if path == "" {
		path = uniqueBackupPath(cfg.dbPath)
	}
	receipt, err := database.CreateSnapshot(ctx, cfg.dbPath, path)
	if err != nil {
		return nil, fmt.Errorf("safety snapshot refused, nothing was written: %w", err)
	}
	return receipt, nil
}

// uniqueBackupPath returns the first free default snapshot path for a database.
// The timestamp alone is not unique: two runs in the same second would collide,
// and the second would have to overwrite the first.
func uniqueBackupPath(dbPath string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	path := fmt.Sprintf("%s.gigahost-backup-%s", dbPath, stamp)
	for i := 1; ; i++ {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return path
		}
		path = fmt.Sprintf("%s.gigahost-backup-%s-%d", dbPath, stamp, i)
	}
}

// emit writes the report as text or JSON.
func emit(stdout io.Writer, cfg config, rep report) error {
	if cfg.jsonOutPath != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfg.jsonOutPath, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	if cfg.asJSON {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(data))
		return err
	}
	writeText(stdout, rep)
	return nil
}

func writeText(w io.Writer, rep report) {
	fmt.Fprintf(w, "database: %s\n", rep.Database)
	fmt.Fprintf(w, "mode: %s\n", rep.Mode)
	if rep.Backup != nil {
		writeSnapshotReceipt(w, "backup", rep.Backup)
	}
	if rep.Restore != nil {
		writeSnapshotReceipt(w, "restored", rep.Restore)
	}
	if rep.Mode == "restored" {
		writeRestoreTail(w, rep)
		return
	}
	writeEvidenceSource(w, rep)
	writePlanTotals(w, rep)
	writeChangeList(w, "\nproposed releases: none\n", "\nproposed releases: %d\n", rep.Released)
	writeChangeList(w, "\nretained reservations: none\n", "\nretained reservations: %d (keep counting)\n", rep.Retained)
	writeUnresolvedBlock(w, rep)
	writeReportTail(w, rep)
}

// writeEvidenceSource states what the conclusions rest on, so an operator cannot
// mistake a local report for a provider answer.
func writeEvidenceSource(w io.Writer, rep report) {
	switch rep.EvidenceSource {
	case "provider_read":
		fmt.Fprintf(w, "evidence: provider read (read-only), %d deployment-status lookup(s)\n", rep.OrderLookups)
	case "", "offline":
		fmt.Fprintf(w, "evidence: none - this report was produced offline from the ledger alone\n")
	default:
		fmt.Fprintf(w, "evidence: %s\n", rep.EvidenceSource)
	}
}

// writePlanTotals prints the cap and the before/after totals.
func writePlanTotals(w io.Writer, rep report) {
	if rep.CapNOK > 0 {
		fmt.Fprintf(w, "monthly cap: %.2f NOK\n", rep.CapNOK)
	} else {
		fmt.Fprintf(w, "monthly cap: not set\n")
	}
	fmt.Fprintf(w, "committed before: %.2f NOK\n", rep.CommittedBefore)
	if rep.Mode == "applied" {
		fmt.Fprintf(w, "committed after:  %.2f NOK\n", rep.CommittedAfter)
	}
	fmt.Fprintf(w, "already released: %d\n", rep.AlreadyReleased)
}

// writeChangeList prints one list of proposed changes with its empty-case text.
func writeChangeList(w io.Writer, empty, header string, changes []gigahostbudget.ProposedChange) {
	if len(changes) == 0 {
		fmt.Fprint(w, empty)
		return
	}
	fmt.Fprintf(w, header, len(changes))
	for _, c := range changes {
		fmt.Fprintf(w, "  record %d  %-14s %-10s %8.2f NOK  %s\n",
			c.RecordID, c.Identity, c.State, c.AmountNOK, c.Explanation)
		if c.ProofNeeded != "" {
			fmt.Fprintf(w, "      proof needed: %s\n", c.ProofNeeded)
		}
	}
}

// writeUnresolvedBlock explains every reservation whose financial outcome is
// unknown, including the fact that this tool cannot release it.
func writeUnresolvedBlock(w io.Writer, rep report) {
	if len(rep.Unresolved) == 0 {
		return
	}
	fmt.Fprintf(w, "\nUNRESOLVED: %d reservation(s) have an unknown financial outcome and stay counted.\n", len(rep.Unresolved))
	if rep.IncompleteTotal {
		fmt.Fprintf(w, "committed before is a LOWER BOUND: at least one counted reservation has no identifiable price.\n")
	}
	if rep.EvidenceSource != "provider_read" {
		fmt.Fprintf(w, "This run holds no provider evidence, so it cannot release them.\n")
	} else {
		fmt.Fprintf(w, "The provider was read, but its answer did not establish that these carry no further charge.\n")
	}
	fmt.Fprintf(w, "Each one needs a provider fact this application can record for the row's own identity:\n")
	fmt.Fprintf(w, "  - a matching provider server reported as terminated or deleted, which ends the recurring commitment.\n")
	fmt.Fprintf(w, "A waitlist order is NOT such a fact: it is unbilled only while it waits and deploys automatically,\n")
	fmt.Fprintf(w, "so it stays a pending commitment until the provider deploys or ends it, and it must keep counting.\n")
	fmt.Fprintf(w, "A provider omission from its deployment status list is not such a fact either: the contract states\n")
	fmt.Fprintf(w, "that endpoint also omits canceled orders and servers that were deleted, and ignores foreign orders.\n")
	fmt.Fprintf(w, "There is no local waiver: a note cannot stand in for provider evidence.\n")
}

// writeReportTail prints warnings, apply errors and the closing line.
func writeReportTail(w io.Writer, rep report) {
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warning)
	}
	for _, e := range rep.ApplyErrors {
		fmt.Fprintf(w, "error: %s\n", e)
	}
	if rep.Mode != "applied" {
		fmt.Fprintf(w, "\nThis was a dry run: nothing was written.\n")
	}
}

// writeSnapshotReceipt prints what a snapshot preserved, so an operator reading a
// backup report can see its integrity result and its limits.
func writeSnapshotReceipt(w io.Writer, label string, receipt *database.SnapshotReceipt) {
	fmt.Fprintf(w, "\n%s: %s\n", label, receipt.Path)
	if receipt.SourcePath != "" {
		fmt.Fprintf(w, "  source:         %s\n", receipt.SourcePath)
	}
	fmt.Fprintf(w, "  bytes:          %d\n", receipt.Bytes)
	fmt.Fprintf(w, "  permissions:    %s\n", receipt.FileMode)
	fmt.Fprintf(w, "  sha256:         %s\n", receipt.SHA256)
	fmt.Fprintf(w, "  journal mode:   %s (self-contained; no -wal/-shm needed)\n", receipt.JournalMode)
	fmt.Fprintf(w, "  integrity:      ok\n")
	fmt.Fprintf(w, "  schema objects: %d\n", len(receipt.SchemaObjects))
	fmt.Fprintf(w, "  tables:         %d\n", len(receipt.Tables))
	for _, t := range receipt.Tables {
		fmt.Fprintf(w, "    %-28s %8d rows\n", t.Name, t.Rows)
	}
	fmt.Fprintf(w, "  ledger orders:  %s\n", ledgerSummary(receipt.Ledger.Orders))
	fmt.Fprintf(w, "  ledger audit:   %s\n", ledgerSummary(receipt.Ledger.Audit))
	if receipt.ForeignKeyViolations > 0 {
		fmt.Fprintf(w, "  foreign keys:   %d violation(s) present in the source state (reported, not changed)\n",
			receipt.ForeignKeyViolations)
	}
	for _, limit := range receipt.Limits {
		fmt.Fprintf(w, "  limit: %s\n", limit)
	}
	if receipt.SourceLedger != nil {
		fmt.Fprintf(w, "  source ledger:  orders %s, audit %s\n",
			ledgerSummary(receipt.SourceLedger.Orders), ledgerSummary(receipt.SourceLedger.Audit))
	}
}

// ledgerSummary renders one ledger table's fingerprint facts compactly.
func ledgerSummary(t database.LedgerTable) string {
	if !t.Present {
		return "table absent"
	}
	return fmt.Sprintf("%d rows, max id %d, %d released, digest %s", t.Rows, t.MaxID, t.Released, shortDigest(t.Digest))
}

// shortDigest keeps a receipt readable while still showing that a digest exists.
func shortDigest(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16]
}

// writeRestoreTail closes a restore report with the operator's next step.
func writeRestoreTail(w io.Writer, rep report) {
	fmt.Fprintf(w, "\nthe snapshot's ledger history was reproduced in %s\n", rep.RestoredTo)
	fmt.Fprintf(w, "this tool did not touch %s and did not replace any live database.\n", rep.Database)
	fmt.Fprintf(w, "next: inspect the restored file yourself before putting it in service.\n")
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warning)
	}
}
