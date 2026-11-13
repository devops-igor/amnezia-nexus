package tunnel

// Durable deploy-add failure (issue #794 group B).
//
// A deploy add persists a backend row and the durable quarantine that keeps it
// unselectable until qualification. If those two facts can commit separately, a
// failure between them (marker write refused, compensating delete refused, or a
// process exit) leaves a row that a restart loads with no quarantine at all, and an
// ordinary handshake-only probe then admits it. These tests inject each failure at
// the real SQLite boundary with triggers and table changes made through a second
// handle, then reopen the file the way startup does and judge the outcome by what a
// background probe sweep selects.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// execSide runs statements through an independent connection to the same file.
func execSide(t *testing.T, path string, stmts ...string) {
	t.Helper()
	side, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open side handle: %v", err)
	}
	defer func() { _ = side.Close() }()
	for _, stmt := range stmts {
		if _, err := side.ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("side statement %q: %v", stmt, err)
		}
	}
}

const (
	dropSettings      = "DROP TABLE settings"
	refuseRowDelete   = "CREATE TRIGGER refuse_row_delete BEFORE DELETE ON backend_tunnels BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END"
	refuseRowInsert   = "CREATE TRIGGER refuse_row_insert BEFORE INSERT ON backend_tunnels BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END"
	clearRowDelete    = "DROP TRIGGER IF EXISTS refuse_row_delete"
	clearRowInsert    = "DROP TRIGGER IF EXISTS refuse_row_insert"
	durableAddKey     = "test-secret-key-1234567890123456"
	durableAddHost    = "192.0.2.241"
	durableAddEndpont = "192.0.2.241:51820"
)

func newDurableAddStore(t *testing.T) (path string, db *database.DB, pool *Pool, hp *HealthProber, sid int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "durable_add.db")
	db, err := database.Open(path, durableAddKey)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, err = db.CreateServer(context.Background(), &models.Server{Name: "durable-add", Host: durableAddHost})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	pool = NewPool(db)
	hp = NewHealthProber(pool, db, DefaultHealthConfig())
	return path, db, pool, hp, sid
}

// TestFailedDeployAddCannotSurviveReloadUnquarantined drives the real deploy add
// with each store failure, then restarts from the file.
func TestFailedDeployAddCannotSurviveReloadUnquarantined(t *testing.T) {
	cases := []struct {
		name   string
		inject []string
	}{
		{"insert-fails", []string{refuseRowInsert}},
		{"marker-write-fails", []string{dropSettings}},
		{"marker-write-and-cleanup-fail", []string{dropSettings, refuseRowDelete}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, db, pool, hp, sid := newDurableAddStore(t)
			execSide(t, path, tc.inject...)

			deploy := context.WithValue(context.Background(), DeployEnrollmentKey, true)
			added, err := pool.AddTunnel(deploy, sid, durableAddEndpont, "deploy-key")
			if err == nil {
				t.Fatal("deploy add reported success although its durable quarantine could not commit")
			}
			if added != nil {
				t.Fatalf("failed deploy add returned a backend: %+v", added)
			}
			if cur, getErr := pool.GetTunnel(sid); getErr == nil && cur != nil {
				t.Fatalf("failed deploy add left backend %d in the running pool", cur.ID)
			}
			if hp.IsPendingEnrollment(sid) {
				t.Fatal("failed deploy add left a runtime quarantine for a backend that was not added")
			}

			// Restart from the file. The injected failures are removed first so the
			// reload is an ordinary startup, and the settings table is recreated by
			// the schema on open.
			execSide(t, path, clearRowDelete, clearRowInsert)
			if err := db.Close(); err != nil {
				t.Fatalf("close store: %v", err)
			}
			r := reloadStore(t, path)
			persisted, err := r.db.GetBackendTunnelByServerID(context.Background(), sid)
			if err != nil {
				t.Fatalf("read persisted backend: %v", err)
			}
			if persisted != nil && !r.prober.IsPendingEnrollment(sid) {
				t.Fatalf("failed deploy add persisted backend %d with no quarantine (status=%s)", persisted.ID, persisted.Status)
			}
			if admittedAfterBackgroundProbe(t, r.prober, r.pool, sid) {
				t.Fatal("a backend whose deploy add failed was admitted after restart without qualification")
			}
			if persisted != nil {
				t.Fatalf("failed deploy add persisted backend %d; the add must commit nothing", persisted.ID)
			}
		})
	}
}

// TestFailedDeployReEnrollmentIsNotPersistedUnquarantined covers the other deploy
// write: re-enrolling an existing backend replaces its identity and resets its
// health. If its quarantine cannot be recorded, the new unqualified identity must
// not be persisted and the call must fail; otherwise a restart admits that identity
// on a handshake-only probe.
func TestFailedDeployReEnrollmentIsNotPersistedUnquarantined(t *testing.T) {
	path, db, pool, _, sid := newDurableAddStore(t)
	before, err := pool.AddTunnel(context.Background(), sid, durableAddEndpont, "qualified-key")
	if err != nil {
		t.Fatalf("seed qualified backend: %v", err)
	}
	execSide(t, path, dropSettings)

	const newEndpoint = "192.0.2.242:51820"
	deploy := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	if _, err := pool.AddTunnel(deploy, sid, newEndpoint, "reenrolled-key"); err == nil {
		t.Fatal("deploy re-enrollment reported success although its quarantine could not be recorded")
	}
	cur, err := pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("read backend: %v", err)
	}
	if cur.Endpoint != before.Endpoint || cur.StateVersion != before.StateVersion || cur.Status != before.Status {
		t.Fatalf("failed re-enrollment changed the running backend: %+v -> %+v", before, cur)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	r := reloadStore(t, path)
	persisted, err := r.db.GetBackendTunnelByServerID(context.Background(), sid)
	if err != nil || persisted == nil {
		t.Fatalf("read persisted backend: %v", err)
	}
	if persisted.Endpoint == newEndpoint && !r.prober.IsPendingEnrollment(sid) {
		t.Fatal("the re-enrolled identity was persisted with no quarantine")
	}
	if persisted.Endpoint != before.Endpoint {
		t.Fatalf("failed re-enrollment persisted the new identity %s", persisted.Endpoint)
	}
}
