package ssh

// A presence refusal can be observed by the request wrapper rather than by the
// validation that calls it: the row is listed when validation reads it, and
// absent by the time the wrapper reads it again. These cases place the change
// exactly in that window, on a real loopback SSH peer, and require the refusal
// to stay a refusal - maintenance parks the server, a command already running
// finishes, and no replacement connection is opened - while a listed control in
// the same run keeps its traffic.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// windowPresenceStore answers for one server: the first `listedReads` reads
// report it listed, later reads report it absent (or fail, from the read named
// by failFrom). Reads of any other server are always listed, so the same run can
// carry a live control.
type windowPresenceStore struct {
	*memoryHostKeyStore
	mu          sync.Mutex
	target      int64
	listedReads int
	failFrom    int
	reads       int
	hardAbsent  bool
}

func (s *windowPresenceStore) IsServerProviderAbsent(_ context.Context, id int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.target {
		return false, nil
	}
	s.reads++
	if s.hardAbsent {
		return true, nil
	}
	if s.listedReads < 0 {
		return false, nil // No window armed: the row is simply listed.
	}
	if s.failFrom > 0 && s.reads >= s.failFrom {
		return false, errors.New("observation store unreachable")
	}
	return s.reads > s.listedReads, nil
}

// arm starts a window: the next listedReads reads of the target are listed, the
// read named by failFrom (when set) and every later read fail instead of
// answering.
func (s *windowPresenceStore) arm(listedReads, failFrom int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads, s.listedReads, s.failFrom, s.hardAbsent = 0, listedReads, failFrom, false
}

func (s *windowPresenceStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// newWindowPresenceStore returns a store whose target row starts listed.
func newWindowPresenceStore(target int64) *windowPresenceStore {
	return &windowPresenceStore{memoryHostKeyStore: newMemoryHostKeyStore(), target: target, listedReads: -1}
}

func TestPoolAbsenceDuringValidationParksInFlightWork(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failFrom int
		wantErr  error
	}{
		{name: "refused", failFrom: 0, wantErr: ErrProviderAbsent},
		{name: "unavailable", failFrom: 2, wantErr: errPresenceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) { testValidationParking(t, tc.failFrom, tc.wantErr) })
	}
}

func testValidationParking(t *testing.T, failFrom int, wantErr error) {
	t.Helper()
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	controlPeer := NewMockSSHServer(t, "root", "pass")
	defer controlPeer.Close()

	store := newWindowPresenceStore(981)
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	row := &models.Server{ID: 981, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	client, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	controlRow := &models.Server{ID: 982, Host: controlPeer.Host(), SSHPort: controlPeer.Port(), SSHUser: "root", SSHPass: "pass"}
	if _, err := pool.Get(ctx, controlRow); err != nil {
		t.Fatal(err)
	}

	started, finish := make(chan struct{}), make(chan struct{})
	var finishOnce sync.Once
	release := func() { finishOnce.Do(func() { close(finish) }) }
	// The peer's command handler blocks until released, so a failed assertion
	// must not leave it holding the fixture open.
	defer release()
	peer.SetCommandHandler("identity-in-flight", func(string, []byte) (string, string, int) {
		close(started)
		<-finish
		return "finished", "", 0
	})
	done := make(chan error, 1)
	go func() {
		out, _, code, err := client.RunCommand(ctx, "identity-in-flight")
		if err == nil && (out != "finished" || code != 0) {
			err = fmt.Errorf("in-flight result changed: %q/%d", out, code)
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// The row changes between validation's own read and the read the request
	// wrapper performs for the keepalive: exactly the window maintenance hits.
	store.arm(1, failFrom)
	pings, connects := peer.keepalives.Load(), peer.connects.Load()
	pool.pingAll()
	if reads := store.readCount(); reads != 2 {
		t.Fatalf("validation read the observation %d time(s), want 2 (listed, then blocked): the window was not exercised", reads)
	}
	if pool.Len() != 2 {
		t.Errorf("pool length %d after blocked validation, want 2: the parked connection was evicted", pool.Len())
	}
	if got := peer.keepalives.Load(); got != pings {
		t.Errorf("blocked validation sent %d keepalive(s) to the server", got-pings)
	}
	if _, err := pool.Get(ctx, row); !errors.Is(err, wantErr) {
		t.Fatalf("checkout after the blocked validation = %v, want %v", err, wantErr)
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("maintenance interrupted in-flight work: %v", err)
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("the refusal opened %d replacement handshake(s)", got-connects)
	}

	// Live control in the same run: the listed row still validates and works.
	before := controlPeer.keepalives.Load()
	pool.pingAll()
	if controlPeer.keepalives.Load() == before {
		t.Error("listed control sent no validation keepalive")
	}
	if pool.Len() != 2 {
		t.Errorf("pool length %d after the control, want 2", pool.Len())
	}
	control, err := pool.Get(ctx, controlRow)
	if err != nil {
		t.Fatal(err)
	}
	runParkingCommand(t, ctx, control)
	if got := peer.connects.Load(); got != connects {
		t.Error("the control caused a connection to the parked server")
	}
}

func TestPoolCheckoutAfterValidationRefusalOpensNoHandshake(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := newWindowPresenceStore(983)
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	row := &models.Server{ID: 983, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	if _, err := pool.Get(ctx, row); err != nil {
		t.Fatal(err)
	}
	// Admission and validation's own read see the row listed; the wrapper's read
	// is refused. A checkout must then refuse without dialling.
	store.arm(2, 0)
	connects := peer.connects.Load()
	client, err := pool.Get(ctx, row)
	if !errors.Is(err, ErrProviderAbsent) || client != nil {
		t.Fatalf("checkout = (%v, %v), want (nil, ErrProviderAbsent)", client, err)
	}
	if reads := store.readCount(); reads != 3 {
		t.Fatalf("checkout read the observation %d time(s), want 3 (admission, validation, then refused): the checkout did not stop at the refusal", reads)
	}
	if pool.Len() != 1 {
		t.Errorf("checkout dropped the parked connection: pool length %d, want 1", pool.Len())
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("checkout opened %d replacement handshake(s) after the refusal", got-connects)
	}

	// A listed row still checks out and serves work in the same run.
	controlPeer := NewMockSSHServer(t, "root", "pass")
	defer controlPeer.Close()
	controlRow := &models.Server{ID: 984, Host: controlPeer.Host(), SSHPort: controlPeer.Port(), SSHUser: "root", SSHPass: "pass"}
	control, err := pool.Get(ctx, controlRow)
	if err != nil {
		t.Fatal(err)
	}
	runParkingCommand(t, ctx, control)
}

func TestDialClientRefusesStaleSnapshotBeforeSocket(t *testing.T) {
	port, accepted := countingListener(t)
	store := newWindowPresenceStore(985)
	store.hardAbsent = true
	id := int64(985)
	// The snapshot was taken while the row was still listed; only the durable
	// observation says it is gone.
	cfg := Config{Host: "127.0.0.1", Port: port, User: "root", Password: "test-password", ServerID: &id, Store: store, presenceStore: store}
	if _, err := dialClient(context.Background(), cfg); !errors.Is(err, ErrProviderAbsent) {
		t.Fatalf("dial on a stale snapshot = %v, want refusal", err)
	}
	if got := atomic.LoadInt32(accepted); got != 0 {
		t.Fatalf("the absent server opened %d connection(s)", got)
	}

	// Live control: the same construction for a listed row reaches the network,
	// which the bare listener answers by failing the SSH handshake.
	liveID := int64(986)
	live := cfg
	live.ServerID = &liveID
	if _, err := dialClient(context.Background(), live); err == nil {
		t.Fatal("expected the bare listener to fail the SSH handshake")
	}
	waitForAttempts(t, accepted, 1)
	if got := atomic.LoadInt32(accepted); got != 1 {
		t.Fatalf("expected exactly one connection attempt (the listed control), got %d", got)
	}
}

func TestPoolStillReplacesGenuineTransportFailure(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour}, newWindowPresenceStore(987))
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	row := &models.Server{ID: 987, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	client, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	runParkingCommand(t, ctx, client)
	connects := peer.connects.Load()

	peer.DisconnectAll()
	deadline := time.Now().Add(10 * time.Second)
	for pool.Len() != 0 && time.Now().Before(deadline) {
		pool.pingAll()
		time.Sleep(5 * time.Millisecond)
	}
	if pool.Len() != 0 {
		t.Fatal("a genuinely dead connection is still pooled")
	}
	fresh, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatalf("checkout after a dead transport: %v", err)
	}
	if peer.connects.Load() <= connects {
		t.Error("the dead transport was not replaced by a new handshake")
	}
	runParkingCommand(t, ctx, fresh)
}
