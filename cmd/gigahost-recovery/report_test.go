package main

// Unit coverage for the pieces of the recovery CLI that no offline end-to-end
// path reaches: the release-reason guard (offline runs propose no change, so the
// guard only ever runs when the shared calculation proposes one), the catalog
// reader, and the report renderers.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// TestReasonForRequiresConclusiveEvidence pins the guard that stands between a
// proposed change and a written release marker.
func TestReasonForRequiresConclusiveEvidence(t *testing.T) {
	tests := []struct {
		name   string
		change gigahostbudget.ProposedChange
		want   string
	}{
		{
			name:   "retained change is not a release",
			change: gigahostbudget.ProposedChange{Action: gigahostbudget.ActionNone, Reason: "provider_terminated"},
			want:   "",
		},
		{
			name:   "release without a reason is refused",
			change: gigahostbudget.ProposedChange{Action: gigahostbudget.ActionRelease, Reason: ""},
			want:   "",
		},
		{
			name: "provider evidence justifies a release",
			change: gigahostbudget.ProposedChange{
				Action: gigahostbudget.ActionRelease, Reason: "provider_terminated",
			},
			want: "provider_terminated",
		},
		{
			name: "an operator note alone is not evidence",
			change: gigahostbudget.ProposedChange{
				Action: gigahostbudget.ActionRelease, Reason: "operator_confirmed_no_charge", Evidence: "",
			},
			want: "",
		},
		{
			name: "an operator note with recorded evidence passes the guard",
			change: gigahostbudget.ProposedChange{
				Action: gigahostbudget.ActionRelease, Reason: "operator_confirmed_no_charge", Evidence: "provider fact",
			},
			want: "operator_confirmed_no_charge",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reasonFor(tc.change); got != tc.want {
				t.Fatalf("reasonFor(%+v) = %q, want %q", tc.change, got, tc.want)
			}
		})
	}
}

// TestLoadPlansReadsAnOfflineCatalog proves the optional catalog file is read as
// given, and that a broken file is an error rather than a silent empty catalog.
func TestLoadPlansReadsAnOfflineCatalog(t *testing.T) {
	dir := t.TempDir()

	if plans, err := loadPlans(""); err != nil || plans != nil {
		t.Fatalf("no catalog path must mean no plans: %v %v", plans, err)
	}

	good := filepath.Join(dir, "catalog.json")
	payload := `[{"product_id":202,"price_id":666,"currency":"NOK","hourly_rate_nok":0.057,"monthly_ceiling_nok":41}]`
	if err := os.WriteFile(good, []byte(payload), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	plans, err := loadPlans(good)
	if err != nil {
		t.Fatalf("loadPlans: %v", err)
	}
	if len(plans) != 1 || plans[0].ProductID != 202 || plans[0].PriceID != 666 ||
		plans[0].MonthlyCeiling != 41 || plans[0].Currency != "NOK" {
		t.Fatalf("catalog not decoded: %+v", plans)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad catalog: %v", err)
	}
	if _, err := loadPlans(bad); err == nil {
		t.Fatal("a malformed catalog must be an error, not an empty plan list")
	}
	if _, err := loadPlans(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("a missing catalog file must be an error")
	}
}

// TestWriteTextRendersBothModes exercises the two report shapes: a plan report
// and a restore report.
func TestWriteTextRendersBothModes(t *testing.T) {
	plan := report{
		Database:        "/tmp/panel.db",
		Mode:            "dry-run",
		CapNOK:          100,
		CommittedBefore: 123,
		Retained: []gigahostbudget.ProposedChange{{
			RecordID: 1, Identity: "10001", State: "held", AmountNOK: 41, Explanation: "held",
		}},
		Unresolved: []gigahostbudget.ProposedChange{{
			RecordID: 2, Identity: "intent_1", State: "unresolved", AmountNOK: 41, Explanation: "unknown",
		}},
		IncompleteTotal: true,
		Warnings:        []string{"offline run"},
		Backup:          &database.SnapshotReceipt{Path: "/tmp/p.db.bak", SHA256: strings.Repeat("a", 64)},
	}
	var buf bytes.Buffer
	writeText(&buf, plan)
	out := buf.String()
	for _, want := range []string{
		"mode: dry-run", "backup: /tmp/p.db.bak", "sha256:", "monthly cap: 100.00 NOK",
		"committed before: 123.00 NOK", "retained reservations: 1", "UNRESOLVED: 1",
		"LOWER BOUND", "warning: offline run", "This was a dry run: nothing was written.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan report is missing %q:\n%s", want, out)
		}
	}

	applied := plan
	applied.Mode = "applied"
	applied.CommittedAfter = 82
	buf.Reset()
	writeText(&buf, applied)
	if !strings.Contains(buf.String(), "committed after:  82.00 NOK") {
		t.Fatalf("applied report is missing the after-total:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "This was a dry run") {
		t.Fatalf("an applied report must not claim it wrote nothing:\n%s", buf.String())
	}

	restore := report{
		Database:   "/tmp/panel.db.gigahost-backup",
		Mode:       "restored",
		RestoredTo: "/tmp/restored/panel.db",
		Restore: &database.SnapshotReceipt{
			Path: "/tmp/restored/panel.db",
			Ledger: database.LedgerState{
				Orders: database.LedgerTable{Present: true, Rows: 3, MaxID: 3, Digest: strings.Repeat("b", 64)},
				Audit:  database.LedgerTable{Present: true, Rows: 2, MaxID: 2, Digest: strings.Repeat("c", 64)},
			},
		},
	}
	buf.Reset()
	writeText(&buf, restore)
	out = buf.String()
	for _, want := range []string{
		"mode: restored", "restored: /tmp/restored/panel.db",
		"ledger orders:  3 rows, max id 3", "ledger audit:   2 rows",
		"did not replace any live database", "inspect the restored file yourself",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("restore report is missing %q:\n%s", want, out)
		}
	}
}

// TestEmitWritesTheJSONPlanToFile proves --out writes the machine-readable plan.
func TestEmitWritesTheJSONPlanToFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "plan.json")
	rep := report{Database: "/tmp/panel.db", Mode: "dry-run", CapNOK: 100}
	var stdout bytes.Buffer
	if err := emit(&stdout, config{asJSON: true, jsonOutPath: out}, rep); err != nil {
		t.Fatalf("emit: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	var decoded report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if decoded.Database != rep.Database || decoded.CapNOK != 100 {
		t.Fatalf("plan file = %+v", decoded)
	}
	if !strings.Contains(stdout.String(), `"mode": "dry-run"`) {
		t.Fatalf("--json must still print to stdout:\n%s", stdout.String())
	}
}

// TestRunUsageErrors covers the argument-level refusals of run().
func TestRunUsageErrors(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no --db", nil, "--db is required"},
		{"missing database file", []string{"--db", filepath.Join(dir, "absent.db")}, "cannot read database"},
		{"unknown flag", []string{"--db", db, "--nope"}, ""},
		{"bad flag value", []string{"--db", db, "--budget", "abc"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tc.args...)
			if code != exitUsage {
				t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitUsage, stderr)
			}
			if tc.want != "" && !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr must mention %q, got %q", tc.want, stderr)
			}
		})
	}

	t.Run("help", func(t *testing.T) {
		code, _, stderr := runCLI(t, "--help")
		if code != exitOK {
			t.Fatalf("--help exit = %d, want 0", code)
		}
		if !strings.Contains(stderr, "-restore-to") {
			t.Fatalf("help must document --restore-to:\n%s", stderr)
		}
	})
}

// TestRunRestoreReportsFailureKeepsSource proves a failed restore reports a
// failure exit and leaves the snapshot readable.
func TestRunRestoreReportsFailureKeepsSource(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)
	if code, _, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply"); code != exitOK {
		t.Fatalf("apply failed: %d %q", code, stderr)
	}
	snapshot := findSnapshot(t, dir)

	// A destination inside a missing directory cannot be created.
	code, _, stderr := runCLI(t, "--db", snapshot, "--restore-to", filepath.Join(dir, "missing", "x.db"))
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	if stderr == "" {
		t.Fatal("a failed restore must explain itself")
	}
	// The snapshot is still a valid, restorable snapshot afterwards.
	if _, err := database.VerifySnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("the snapshot was damaged by the failed restore: %v", err)
	}
}

// TestApplyProposedReleasesWritesOnlyJustifiedChanges drives the write path
// directly. An offline run never proposes a release, so the guard that decides
// whether a proposal may be written is only observable by handing it changes.
//
// The three outcomes are asserted separately: a justified release is written with
// its audit row, a change with no conclusive reason is refused and reported, and a
// release of an already-released record is a no-op rather than an error.
func TestApplyProposedReleasesWritesOnlyJustifiedChanges(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "panel.db")
	ledgerFixture(t, dbPath)
	ctx := t.Context()

	db, err := database.Open(dbPath, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	rep := report{}
	changes := []gigahostbudget.ProposedChange{
		{RecordID: 1, OrderID: "10001", Action: gigahostbudget.ActionRelease, Reason: "provider_terminated",
			Explanation: "server ended"},
		{RecordID: 2, OrderID: "intent_1", Action: gigahostbudget.ActionRelease, Reason: "",
			Explanation: "no evidence"},
		{RecordID: 99, OrderID: "missing", Action: gigahostbudget.ActionRelease, Reason: "provider_terminated",
			Explanation: "row does not exist"},
	}
	applyProposedReleases(ctx, db, changes, &rep)

	rows, err := db.ListGigahostOrderAudit(ctx, 1)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	// The fixture already carries one historic audit row for record 1, so exactly
	// one new row means the release wrote one entry.
	if len(rows) != 2 {
		t.Fatalf("the justified release must add exactly one audit row, got %+v", rows)
	}
	if rows[0].Reason != "provider_terminated" || rows[0].Detail != "server ended" {
		t.Fatalf("the new audit row does not record the release: %+v", rows[0])
	}
	if len(rep.ApplyErrors) != 2 {
		t.Fatalf("both refused changes must be reported, got %v", rep.ApplyErrors)
	}
	if !strings.Contains(strings.Join(rep.ApplyErrors, " "), "no conclusive evidence") {
		t.Fatalf("a reasonless change must be refused explicitly: %v", rep.ApplyErrors)
	}

	// A repeated run over the same justified change is a visible no-op.
	rep2 := report{}
	applyProposedReleases(ctx, db, changes[:1], &rep2)
	if len(rep2.ApplyErrors) != 0 {
		t.Fatalf("releasing an already-released row must not be an error: %v", rep2.ApplyErrors)
	}
	rowsAfter, err := db.ListGigahostOrderAudit(ctx, 1)
	if err != nil {
		t.Fatalf("re-read audit: %v", err)
	}
	if len(rowsAfter) != 2 {
		t.Fatalf("a repeated release wrote another audit row: %d", len(rowsAfter))
	}
}

// TestFillPlanReportSeparatesUnresolved pins the report split: unresolved
// reservations appear in their own list so an operator cannot read a retained
// count as a decision.
func TestFillPlanReportSeparatesUnresolved(t *testing.T) {
	proposal := gigahostbudget.Proposal{
		CommittedBefore: 123,
		CommittedAfter:  123,
		IncompleteTotal: true,
		Changes:         nil,
		Retained: []gigahostbudget.ProposedChange{
			{RecordID: 1, State: gigahostbudget.StateActive},
			{RecordID: 2, State: gigahostbudget.StateUnresolved},
			{RecordID: 3, State: gigahostbudget.StateUnresolved},
		},
	}
	orders := []models.GigahostOrder{{ID: 1}, {ID: 2, ReleasedAt: "2026-11-01T00:00:00Z"}}
	rep := report{}
	fillPlanReport(&rep, proposal, orders)

	if len(rep.Retained) != 3 {
		t.Fatalf("retained = %d, want 3", len(rep.Retained))
	}
	if len(rep.Unresolved) != 2 {
		t.Fatalf("unresolved = %d, want 2", len(rep.Unresolved))
	}
	if len(rep.Released) != 0 {
		t.Fatalf("released must be an empty slice, got %d entries", len(rep.Released))
	}
	if rep.AlreadyReleased != 1 {
		t.Fatalf("already released = %d, want 1", rep.AlreadyReleased)
	}
	if !rep.IncompleteTotal || rep.CommittedBefore != 123 {
		t.Fatalf("totals were not carried over: %+v", rep)
	}
}
