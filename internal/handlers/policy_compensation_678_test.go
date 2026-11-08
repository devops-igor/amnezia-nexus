package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests cover the two compensation properties F678-02 required beyond
// "write the old value back": the write must survive a canceled request
// context, and it must never discard a record a later save already accepted.
//
// They drive the real SQLite settings table through the unexported compensation
// helper, because the handler-level path (router package) cannot stage
// concurrent saves inside one request.

const compensationTestSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newPolicyTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "compensation.db"), compensationTestSecretKey)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func storePolicySettings(t *testing.T, db *database.DB, settings policy.Settings) {
	t.Helper()
	if err := db.SetSetting(context.Background(), policy.SettingsKey, settings); err != nil {
		t.Fatalf("set policy settings: %v", err)
	}
}

func readPolicySettings(t *testing.T, db *database.DB) policy.Settings {
	t.Helper()
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("get policy settings: %v", err)
	}
	return stored
}

// TestRestorePolicySettingsWorksAfterRequestCancellation is the F678-02 root
// property: compensation must not inherit the canceled request context.
//
// The context passed in is already canceled, exactly as it is when a client
// disconnects or the shipped 60-second request deadline fires during a slow
// activation. On c161a2a the rollback reused that context and database/sql
// refused the write, so the rejected record stayed durable.
func TestRestorePolicySettingsWorksAfterRequestCancellation(t *testing.T) {
	db := newPolicyTestDB(t)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

	previous := policy.DefaultSettings()
	previous.Preset = policy.PresetGeoblock
	if err := db.SetSetting(context.Background(), policy.SettingsKey, previous); err != nil {
		t.Fatalf("seed previous: %v", err)
	}

	rejected := previous
	rejected.Enabled = true
	rejected.Preset = policy.PresetCustom
	rejected.CustomURLs = []string{"https://rejected.example.invalid/list.lst"}
	storePolicySettings(t, db, rejected)

	prevRec := previousPolicyRecord{settings: previous, present: true}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // already-canceled, like a disconnected client

	if err := h.restorePolicySettings(canceledCtx, prevRec, rejected); err != nil {
		t.Fatalf("compensation under a canceled request context failed: %v", err)
	}

	got := readPolicySettings(t, db)
	if got.Enabled || got.Preset != policy.PresetGeoblock || len(got.CustomURLs) != 0 {
		t.Fatalf("rejected record was not compensated: %+v", got)
	}
}

// TestRestorePolicySettingsLeavesLaterAcceptedSaveIntact guards the other half of
// the recommendation: compensation must not overwrite a newer configuration.
//
// Two admins (or an admin and a backup restore) can interleave; the slower
// request must not clobber the faster request's accepted record just because its
// own activation failed afterwards.
func TestRestorePolicySettingsLeavesLaterAcceptedSaveIntact(t *testing.T) {
	db := newPolicyTestDB(t)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

	previous := policy.DefaultSettings()
	previous.Preset = policy.PresetGeoblock
	storePolicySettings(t, db, previous)

	written := previous
	written.Enabled = true
	written.Preset = policy.PresetCustom
	written.CustomURLs = []string{"https://slow-request.example.invalid/list.lst"}
	storePolicySettings(t, db, written)

	// A second, later save wins the race and is fully accepted.
	later := previous
	later.Preset = policy.PresetAntifilterDomains
	later.SyncInterval = int64(2 * time.Hour / time.Second)
	storePolicySettings(t, db, later)

	prevRec := previousPolicyRecord{settings: previous, present: true}
	err := h.restorePolicySettings(context.Background(), prevRec, written)
	if err == nil {
		t.Fatal("compensation overwrote a later accepted save instead of reporting it superseded")
	}
	if !errors.Is(err, errPolicySettingsSuperseded) {
		t.Fatalf("compensation failed for an unexpected reason: %v", err)
	}

	got := readPolicySettings(t, db)
	if got.Preset != policy.PresetAntifilterDomains {
		t.Fatalf("later accepted save was clobbered by compensation: got preset %q, want %q", got.Preset, policy.PresetAntifilterDomains)
	}
	if got.SyncInterval != later.SyncInterval {
		t.Fatalf("later accepted save lost its interval: got %d, want %d", got.SyncInterval, later.SyncInterval)
	}
}

// TestRestorePolicySettingsDeletesRowThatDidNotExist keeps compensation faithful
// to a fresh install: "no record" is a real previous state, and materializing a
// default record would outlive the rejected request as operator intent.
func TestRestorePolicySettingsDeletesRowThatDidNotExist(t *testing.T) {
	db := newPolicyTestDB(t)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

	written := policy.DefaultSettings()
	written.Enabled = true
	written.Preset = policy.PresetCustom
	written.CustomURLs = []string{"https://fresh-install.example.invalid/list.lst"}
	storePolicySettings(t, db, written)

	if err := h.restorePolicySettings(context.Background(), previousPolicyRecord{}, written); err != nil {
		t.Fatalf("compensation for an absent previous record failed: %v", err)
	}

	raw, found, err := db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil {
		t.Fatalf("read raw setting: %v", err)
	}
	if found && raw.Valid && raw.String != "" {
		t.Fatalf("compensation left a record behind where none existed: %q", raw.String)
	}
}

// TestLoadPolicyRecordReportsPresence proves the presence flag compensation
// depends on: the default record and an actually-stored record are different
// states, even though they decode to equal Settings values.
func TestLoadPolicyRecordReportsPresence(t *testing.T) {
	db := newPolicyTestDB(t)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

	rec, err := h.loadPolicyRecord(context.Background())
	if err != nil {
		t.Fatalf("loadPolicyRecord on empty db: %v", err)
	}
	if rec.present {
		t.Fatal("fresh install reported a stored policy record")
	}
	if rec.settings.Enabled {
		t.Fatal("fresh install reported policy routing enabled")
	}

	stored := policy.DefaultSettings()
	stored.Preset = policy.PresetGeoblock
	storePolicySettings(t, db, stored)

	rec, err = h.loadPolicyRecord(context.Background())
	if err != nil {
		t.Fatalf("loadPolicyRecord after store: %v", err)
	}
	if !rec.present {
		t.Fatal("stored policy record reported absent")
	}
	if rec.settings.Preset != policy.PresetGeoblock {
		t.Fatalf("loaded preset %q, want %q", rec.settings.Preset, policy.PresetGeoblock)
	}
}

// TestRollbackPolicySettingsRendersEachOutcome exercises the three outcomes the
// compensation path must distinguish. The router-level test covers the "restored"
// branch end to end; these drive the remaining branches (later accepted save,
// and an unrecoverable compensation failure) through the real response writer and
// real SQLite, which is where the operator-visible status code and audit result
// are decided.
func TestRollbackPolicySettingsRendersEachOutcome(t *testing.T) {
	t.Run("restored previous record answers 422", func(t *testing.T) {
		db := newPolicyTestDB(t)
		h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

		previous := policy.DefaultSettings()
		previous.Preset = policy.PresetGeoblock
		storePolicySettings(t, db, previous)

		written := previous
		written.Enabled = true
		written.Preset = policy.PresetCustom
		written.CustomURLs = []string{"https://restored.example.invalid/x.lst"}
		storePolicySettings(t, db, written)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", nil)
		h.rollbackPolicySettings(w, req, previousPolicyRecord{settings: previous, present: true},
			written, errors.New("activation refused"))

		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("restored outcome = %d, want 422; body=%s", w.Code, w.Body.String())
		}
		if got := readPolicySettings(t, db); got.Preset != policy.PresetGeoblock {
			t.Fatalf("previous record was not restored: %+v", got)
		}
	})

	t.Run("later accepted save answers 422 without clobbering it", func(t *testing.T) {
		db := newPolicyTestDB(t)
		h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

		previous := policy.DefaultSettings()
		previous.Preset = policy.PresetGeoblock
		storePolicySettings(t, db, previous)

		written := previous
		written.Enabled = true
		written.Preset = policy.PresetCustom
		written.CustomURLs = []string{"https://superseded.example.invalid/x.lst"}
		storePolicySettings(t, db, written)

		later := previous
		later.Preset = policy.PresetAntifilterDomains
		storePolicySettings(t, db, later)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", nil)
		h.rollbackPolicySettings(w, req, previousPolicyRecord{settings: previous, present: true},
			written, errors.New("activation refused"))

		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("superseded outcome = %d, want 422; body=%s", w.Code, w.Body.String())
		}
		if got := readPolicySettings(t, db); got.Preset != policy.PresetAntifilterDomains {
			t.Fatalf("later accepted save was clobbered: %+v", got)
		}
	})

	t.Run("unrecoverable compensation answers 500 and says so", func(t *testing.T) {
		db := newPolicyTestDB(t)
		h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

		written := policy.DefaultSettings()
		written.Enabled = true
		written.Preset = policy.PresetCustom
		written.CustomURLs = []string{"https://unrecoverable.example.invalid/x.lst"}
		storePolicySettings(t, db, written)

		// Close the database so compensation cannot re-read or write. This is the
		// "rollback itself failed" case: the rejected record may still be durable
		// while the runtime stayed on the previous policy.
		if err := db.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", nil)
		h.rollbackPolicySettings(w, req, previousPolicyRecord{settings: policy.DefaultSettings(), present: true},
			written, errors.New("activation refused"))

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("unrecoverable outcome = %d, want 500; body=%s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "state_inconsistent") {
			t.Fatalf("500 body does not name the inconsistent state: %s", body)
		}
	})
}

// TestLoadPolicyRecordSurfacesDecodeError keeps a corrupt row from being silently
// read as the disabled default, which would make an enable look like a fresh
// install and lose the durable baseline compensation has to restore.
func TestLoadPolicyRecordSurfacesDecodeError(t *testing.T) {
	db := newPolicyTestDB(t)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, db: db}

	if _, err := db.SQLDB().ExecContext(context.Background(),
		"INSERT INTO settings (key, value) VALUES (?, ?)", policy.SettingsKey, "{not json"); err != nil {
		t.Fatalf("write corrupt row: %v", err)
	}

	if _, err := h.loadPolicyRecord(context.Background()); err == nil {
		t.Fatal("corrupt stored record was silently treated as absent")
	}
}
