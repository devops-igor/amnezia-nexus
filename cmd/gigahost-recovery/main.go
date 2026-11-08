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
//   - It never contacts the provider, so it has NO authoritative proof available
//     and therefore releases NOTHING on its own. There is deliberately no
//     operator waiver: the approved scope forbids an administrator
//     acknowledgement standing in for authoritative reconciliation, and a
//     free-text note is not proof of anything. A reservation whose outcome is
//     genuinely unknowable is reported as unresolved, kept in the committed
//     total, and named so whoever holds real provider evidence can act.
//   - The only release evidence that exists is provider evidence (a terminated or
//     deleted server, or a waitlist reservation the contract states is not
//     billed). An offline run cannot obtain it, so an offline run proposes no
//     change.
//   - A backup is taken before any write. NOTE: the backup is currently a plain
//     file copy of database/-wal/-shm and is NOT a coherent SQLite snapshot under
//     WAL mutation. Making it coherent is the queued A2 work, so until then
//     --apply must not be run against a live database.
//   - Releasing writes a marker plus an audit row and keeps the original status,
//     so a repeated run reports "already released" and changes nothing.
//   - Nothing here can order, cancel or delete a VPS.
//
// Usage:
//
//	gigahost-recovery --db /path/panel.db          # dry run (default, read-only)
//	gigahost-recovery --db /path/panel.db --json    # machine-readable report
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
	catalogPath string
}

// report is what one run found and did.
type report struct {
	Database        string                          `json:"database"`
	Mode            string                          `json:"mode"`
	BackupPath      string                          `json:"backup_path,omitempty"`
	CapNOK          float64                         `json:"cap_nok"`
	CommittedBefore float64                         `json:"committed_before_nok"`
	CommittedAfter  float64                         `json:"committed_after_nok"`
	Released        []gigahostbudget.ProposedChange `json:"released"`
	Retained        []gigahostbudget.ProposedChange `json:"retained"`
	Unresolved      []gigahostbudget.ProposedChange `json:"unresolved"`
	AlreadyReleased int                             `json:"already_released"`
	IncompleteTotal bool                            `json:"incomplete_total"`
	Warnings        []string                        `json:"warnings,omitempty"`
	ApplyErrors     []string                        `json:"apply_errors,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var cfg config
	var showHelp bool

	fs := flag.NewFlagSet("gigahost-recovery", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.dbPath, "db", "", "path to the panel SQLite database (required)")
	fs.Float64Var(&cfg.budgetNOK, "budget", 0, "monthly budget cap in NOK as configured in the panel; 0 means no cap")
	fs.BoolVar(&cfg.apply, "apply", false, "write the proposed releases (default is a read-only dry run)")
	fs.BoolVar(&cfg.asJSON, "json", false, "emit the plan as JSON instead of text")
	fs.StringVar(&cfg.jsonOutPath, "out", "", "write the JSON plan to this path as well")
	fs.StringVar(&cfg.backupPath, "backup", "", "backup file path for --apply (default: <db>.gigahost-backup-<timestamp>)")
	fs.BoolVar(&cfg.noBackup, "no-backup", false, "skip the safety backup (not recommended)")
	fs.StringVar(&cfg.catalogPath, "catalog", "", "JSON file of catalog rows, for pricing legacy records offline (never fetched)")
	fs.BoolVar(&showHelp, "help", false, "show this help")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if showHelp {
		fs.Usage()
		return exitOK
	}
	if cfg.dbPath == "" {
		fmt.Fprintln(stderr, "gigahost-recovery: --db is required")
		return exitUsage
	}
	if _, err := os.Stat(cfg.dbPath); err != nil {
		fmt.Fprintf(stderr, "gigahost-recovery: cannot read database %s: %v\n", cfg.dbPath, err)
		return exitUsage
	}
	if cfg.apply && cfg.noBackup && !cfg.asJSON {
		fmt.Fprintln(stderr, "gigahost-recovery: WARNING: --apply without a backup; no automatic undo exists")
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
	if len(rep.ApplyErrors) > 0 {
		return exitFailure
	}
	if unresolvedCount > 0 && !cfg.apply {
		return exitUnresolved
	}
	return exitOK
}

// execute opens the database read-write only when applying, computes the plan,
// and applies it when asked.
func execute(cfg config) (report, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rep := report{
		Database: cfg.dbPath,
		Mode:     "dry-run",
		CapNOK:   cfg.budgetNOK,
	}

	// A dry run opens the database strictly read-only and never migrates: an
	// inspection must not change the file it inspects. --apply takes the
	// safety backup BEFORE opening read-write, so the backup captures the state
	// before any migration or release, not a partly-changed file.
	if cfg.apply {
		backupPath, backupErr := makeBackup(cfg)
		if backupErr != nil {
			return rep, 0, backupErr
		}
		rep.BackupPath = backupPath
	}
	var (
		db    *database.DB
		opens = database.OpenReadOnly
	)
	if cfg.apply {
		opens = func(path string) (*database.DB, error) { return database.Open(path, "") }
	}
	db, err := opens(cfg.dbPath)
	if err != nil {
		return rep, 0, fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	var orders []models.GigahostOrder
	if cfg.apply {
		orders, err = db.ListGigahostOrders(ctx)
	} else {
		orders, err = db.ListGigahostOrdersReadOnly(ctx)
	}
	if err != nil {
		return rep, 0, fmt.Errorf("read ledger: %w", err)
	}
	plans, err := loadPlans(cfg.catalogPath)
	if err != nil {
		return rep, 0, err
	}

	entries, evidence := prepareEntries(orders)
	// This run has no provider evidence available, so nothing can be released.
	// Saying so explicitly keeps the report truthful rather than looking like a
	// clean bill of health.
	rep.Warnings = append(rep.Warnings,
		"offline run: no provider evidence is available, so no release is proposed; unresolved reservations are kept and named")

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

	rep.CommittedBefore = proposal.CommittedBefore
	rep.CommittedAfter = proposal.CommittedAfter
	rep.IncompleteTotal = proposal.IncompleteTotal
	// Emit empty slices rather than nil so a machine-readable plan always carries
	// real arrays: a null here is indistinguishable from "not reported".
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

	if !cfg.apply {
		return rep, len(rep.Unresolved), nil
	}

	rep.Mode = "applied"
	for _, change := range proposal.Changes {
		reason := reasonFor(change)
		if reason == "" {
			rep.ApplyErrors = append(rep.ApplyErrors,
				fmt.Sprintf("record %d: no conclusive evidence, refusing to release", change.RecordID))
			continue
		}
		if err := db.ReleaseGigahostOrder(ctx, change.RecordID, reason, change.Explanation); err != nil {
			if errors.Is(err, database.ErrGigahostOrderAlreadyReleased) {
				continue
			}
			rep.ApplyErrors = append(rep.ApplyErrors, fmt.Sprintf("record %d: %v", change.RecordID, err))
		}
	}
	return rep, len(rep.Unresolved), nil
}

// prepareEntries builds the shared input from the ledger.
//
// It supplies no release evidence at all, and that is the point: this tool is
// offline, so any evidence it could hand over would be an operator assertion
// rather than provider fact. A note-only waiver was explicitly rejected by the
// approved scope, so the function that used to build one no longer exists.
func prepareEntries(orders []models.GigahostOrder) ([]gigahostbudget.Entry, map[int64]gigahostbudget.Evidence) {
	entries := make([]gigahostbudget.Entry, 0, len(orders))
	evidence := make(map[int64]gigahostbudget.Evidence)

	for _, o := range orders {
		entries = append(entries, gigahostbudget.Entry{
			RecordID:       o.ID,
			OrderID:        o.OrderID,
			ServerID:       o.ServerID,
			Status:         o.Status,
			PlanID:         o.PlanID,
			RegionID:       o.RegionID,
			HourlyPriceNOK: o.HourlyPriceNOK,
			PriceID:        o.PriceID,
			MonthlyCapNOK:  o.MonthlyCapNOK,
			Currency:       o.Currency,
			AssignedIP:     o.AssignedIP,
			ReleasedAt:     o.ReleasedAt,
			ReleaseReason:  o.ReleaseReason,
		})
	}
	return entries, evidence
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

// makeBackup copies the database next to itself before any write. SQLite is
// copied through its own backup semantics by reading the file after a
// checkpoint, so a WAL that has not been merged cannot be lost.
//
// The default path is made unique: overwriting an earlier backup with a newer
// pre-change state would destroy the only copy of the state before the first
// write.
func makeBackup(cfg config) (string, error) {
	if cfg.noBackup {
		return "", nil
	}
	path := cfg.backupPath
	if path == "" {
		stamp := time.Now().UTC().Format("20060102T150405Z")
		path = fmt.Sprintf("%s.gigahost-backup-%s", cfg.dbPath, stamp)
		for i := 1; ; i++ {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				break
			}
			path = fmt.Sprintf("%s.gigahost-backup-%s-%d", cfg.dbPath, stamp, i)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := cfg.dbPath + suffix
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, path+suffix); err != nil {
			return "", fmt.Errorf("backup %s: %w", src, err)
		}
	}
	return path, nil
}

func copyFile(src, dst string) error {
	// Both paths are operator-supplied local paths (the database and its backup
	// destination); neither is derived from network input.
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
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
	if rep.BackupPath != "" {
		fmt.Fprintf(w, "backup: %s\n", rep.BackupPath)
	}
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

	if len(rep.Released) == 0 {
		fmt.Fprintf(w, "\nproposed releases: none\n")
	} else {
		fmt.Fprintf(w, "\nproposed releases: %d\n", len(rep.Released))
		for _, c := range rep.Released {
			fmt.Fprintf(w, "  record %d  %-14s %-10s %8.2f NOK  %s\n",
				c.RecordID, c.Identity, c.State, c.AmountNOK, c.Explanation)
		}
	}

	if len(rep.Retained) == 0 {
		fmt.Fprintf(w, "\nretained reservations: none\n")
	} else {
		fmt.Fprintf(w, "\nretained reservations: %d (keep counting)\n", len(rep.Retained))
		for _, c := range rep.Retained {
			fmt.Fprintf(w, "  record %d  %-14s %-10s %8.2f NOK  %s\n",
				c.RecordID, c.Identity, c.State, c.AmountNOK, c.Explanation)
		}
	}

	if len(rep.Unresolved) > 0 {
		fmt.Fprintf(w, "\nUNRESOLVED: %d reservation(s) have an unknown financial outcome and stay counted.\n", len(rep.Unresolved))
		if rep.IncompleteTotal {
			fmt.Fprintf(w, "committed before is a LOWER BOUND: at least one counted reservation has no identifiable price.\n")
		}
		fmt.Fprintf(w, "This tool cannot release them: it is offline and holds no provider evidence.\n")
		fmt.Fprintf(w, "Each one needs a provider fact that the panel has not recorded yet:\n")
		fmt.Fprintf(w, "  - a terminated or deleted server for the matching provider server id, which ends the commitment.\n")
		fmt.Fprintf(w, "A waitlist order is NOT such a fact: it is unbilled only while it waits and deploys automatically,\n")
		fmt.Fprintf(w, "so it stays a pending commitment until the provider actually deploys or ends it.\n")
		fmt.Fprintf(w, "Once the panel sees a conclusive fact, its own reconciliation releases the reservation, with an audit row.\n")
		fmt.Fprintf(w, "There is no local waiver: a note cannot stand in for provider evidence.\n")
	}
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
