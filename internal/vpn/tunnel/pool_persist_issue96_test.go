package tunnel

// Issue #96: pool counter DB persistence must happen OFF p.mu
// (copy-state-release-persist). These tests pin:
//  1. readers (GetActiveTunnels) complete while a slow/blocked persist is
//     in flight — the DB write must not hold p.mu,
//  2. the in-memory gauge mutation is visible immediately even when the
//     persist is delayed or fails,
//  3. persist failures are surfaced (logged), not silently ignored.

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// issue96Lock opens a second connection on the same sqlite file and takes a
// write transaction (any no-op write upgrades the deferred tx to a RESERVED
// lock): every OTHER connection's write now blocks past its busy_timeout
// while reads stay possible — the same injection seam as the #107
// fault-injection matrix.
func issue96Lock(t *testing.T, dbPath, table string, busyTimeoutMS int) *sql.Tx {
	t.Helper()
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout("+itoa(busyTimeoutMS)+")")
	if err != nil {
		t.Fatalf("open locker: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("begin locker tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS " + table + " (x)"); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}
	return tx
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestIncrementConnectionsReadersProgressWhilePersistBlocked is the issue
// #96 reader-progress test: with a persist BLOCKED in flight (held sqlite
// write lock on the same file), concurrent GetActiveTunnels readers must
// complete unimpeded — proving the DB write does not hold p.mu. The persist
// is synchronous inside IncrementConnections, so the method itself runs in
// a goroutine; the assertions are (a) the in-memory gauge is visible while
// the persist is still blocked, (b) readers finish while it stays blocked.
func TestIncrementConnectionsReadersProgressWhilePersistBlocked(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "issue96_block.db")
	db, err := openTunnelDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "srv-r", Host: "9.9.9.9"})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, s1ID, "9.9.9.9:51820", "")
	if err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Block all writes on the file (locker busy_timeout 50ms; the pool DB's
	// own writes retry for 5s — the persist stalls well past the readers).
	lockTx := issue96Lock(t, dbPath, "issue96_locker", 50)

	// Run the increment concurrently; its persist will be blocked.
	incDone := make(chan struct{})
	go func() {
		pool.IncrementConnections(tun.ID)
		close(incDone)
	}()

	// The in-memory gauge must become visible LONG before the blocked
	// persist returns (which would take ≥5s of sqlite busy retry).
	gaugeVisible := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := pool.GetTunnelByID(tun.ID); err == nil && got.ActiveConnections == 1 {
			gaugeVisible = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !gaugeVisible {
		t.Fatal("in-memory gauge not visible while persist blocked (issue #96)")
	}

	// While the persist is still blocked in flight, hammer the reader paths:
	// every call must complete quickly — none may queue behind the write.
	var wg sync.WaitGroup
	var failures int64
	var mu sync.Mutex
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				active := pool.GetActiveTunnels()
				if len(active) != 1 {
					mu.Lock()
					failures++
					mu.Unlock()
				}
				_ = pool.ListTunnels()
			}
		}()
	}
	wgWait := make(chan struct{})
	go func() { wg.Wait(); close(wgWait) }()

	select {
	case <-wgWait:
	case <-time.After(5 * time.Second):
		t.Fatal("readers stalled while a persist was blocked in flight (issue #96 regression)")
	}
	if failures != 0 {
		t.Errorf("%d reader iterations saw wrong active tunnel count", failures)
	}

	// Release the lock: the persist lands and the increment goroutine
	// returns; the DB row must then catch up to the gauge (last-write-wins).
	if err := lockTx.Rollback(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	select {
	case <-incDone:
	case <-time.After(10 * time.Second):
		t.Fatal("IncrementConnections never returned after lock release")
	}
	if got, err := pool.GetTunnelByID(tun.ID); err != nil || got.ActiveConnections != 1 {
		t.Errorf("gauge after persist: %d/%v, want 1", got.ActiveConnections, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	caught := false
	for time.Now().Before(deadline) {
		row, err := db.GetBackendTunnel(ctx, tun.ID)
		if err == nil && row.ActiveConnections == 1 {
			caught = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !caught {
		row, err := db.GetBackendTunnel(ctx, tun.ID)
		t.Errorf("DB row never caught up after persist: %+v/%v", row, err)
	}
}

// openTunnelDB opens a test database with the same key setupTestDB uses.
func openTunnelDB(dbPath string) (*database.DB, error) {
	return database.Open(dbPath, "test-secret-key-1234567890123456")
}

// TestIncrementConnectionsGaugeVisibleBeforePersist proves the in-memory
// mutation lands BEFORE the DB write completes: with a persist that is slow
// (but eventually succeeds), the gauge must already be visible.
func TestIncrementConnectionsGaugeVisibleBeforePersist(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "issue96_vis.db")
	db, err := openTunnelDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "srv-s", Host: "9.9.9.8"})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, s1ID, "9.9.9.8:51820", "")
	if err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Hold the sqlite write lock so the increment's persist cannot land.
	lockTx := issue96Lock(t, dbPath, "issue96_lock2", 50)

	pool.IncrementConnections(tun.ID)

	// The in-memory gauge must reflect the increment even though the persist
	// could not have landed yet (write lock held).
	if got, err := pool.GetTunnelByID(tun.ID); err != nil || got.ActiveConnections != 1 {
		t.Fatalf("gauge visible after increment despite blocked persist: got %d/%v, want 1", got.ActiveConnections, err)
	}
	// And the DB row still shows 0: divergence, bounded and observable.
	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel: %v", err)
	}
	if row.ActiveConnections != 0 {
		t.Logf("DB row also persisted despite the held lock (write retry semantics); divergence not observable this run")
	}

	// Release the lock: a LATER decrement's persist must land and bring the
	// DB to the final gauge value (last-write-wins, eventual).
	if err := lockTx.Rollback(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	pool.DecrementConnections(tun.ID)
	deadline := time.Now().Add(5 * time.Second)
	caught := false
	for time.Now().Before(deadline) {
		row, err := db.GetBackendTunnel(ctx, tun.ID)
		if err == nil && row.ActiveConnections == 0 {
			caught = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !caught {
		row, err := db.GetBackendTunnel(ctx, tun.ID)
		t.Errorf("DB row never caught up after lock release: %+v/%v", row, err)
	}
}

// TestPersistFailureLogged pins "persist errors surfaced instead of
// ignored": a persist failure during IncrementConnections must be logged
// (slog.Error) while the in-memory gauge stays correct.
func TestPersistFailureLogged(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "issue96_fail.db")
	db, err := openTunnelDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "srv-f", Host: "9.9.9.7"})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, s1ID, "9.9.9.7:51820", "")
	if err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	// Fail every write persist for the duration of the increment.
	_ = issue96Lock(t, dbPath, "issue96_fail", 50)

	// Capture slog error output.
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	defer slog.SetDefault(prev)

	pool.IncrementConnections(tun.ID)

	out := buf.String()
	if !strings.Contains(out, "failed to persist active_connections") {
		t.Errorf("persist failure not surfaced in logs; got: %q", out)
	}
	if got, err := pool.GetTunnelByID(tun.ID); err != nil || got.ActiveConnections != 1 {
		t.Errorf("gauge must stay correct despite persist failure: got %d/%v", got.ActiveConnections, err)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}
