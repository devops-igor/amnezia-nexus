package ssh

// The presence gate shares the validation budget with the peer's reply, and an
// observation lookup legitimately waits on the database. These cases hold that
// second read open past the budget - the crossing case - and require the
// outcome to stay "unknown": the entry is not retired, the running command keeps
// its exit status and nothing new is sent or dialled. A lookup that fails rather
// than hangs must reach the same place, and a listed control in the same run
// must still be measured.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// The timings exercised by these proofs. They are short so the boundary can be
// crossed tightly: the held read outlives the budget by six times, and the
// budget is far above any ordinary loopback reply.
const (
	testReplyBudget = 150 * time.Millisecond
	testGateHold    = 900 * time.Millisecond
)

// gatedPresenceStore answers for one server, holds one observation read open
// until the test releases it, and can fail a later read instead. Reads of any
// other server are always listed, so the same run carries a live control.
type gatedPresenceStore struct {
	*memoryHostKeyStore
	mu          sync.Mutex
	target      int64
	listedReads int // reads answered "listed" before the row turns absent; <0 = never
	gateRead    int // 1-based read held open until release; 0 = none
	failRead    int // 1-based read that fails instead of answering; 0 = none
	reads       int
	release     chan struct{}
	blocked     chan struct{}
	gateOnce    sync.Once
}

func newGatedPresenceStore(target int64) *gatedPresenceStore {
	return &gatedPresenceStore{
		memoryHostKeyStore: newMemoryHostKeyStore(),
		target:             target,
		listedReads:        -1,
		release:            make(chan struct{}),
		blocked:            make(chan struct{}),
	}
}

// arm starts a window: the next listedReads reads answer "listed", the read
// named by gateRead waits for releaseGate, and the read named by failRead (and
// every later one) fails. The row is absent once the listed window is spent.
func (s *gatedPresenceStore) arm(listedReads, gateRead, failRead int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads, s.listedReads, s.gateRead, s.failRead = 0, listedReads, gateRead, failRead
}

func (s *gatedPresenceStore) releaseGate() { close(s.release) }

func (s *gatedPresenceStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *gatedPresenceStore) IsServerProviderAbsent(_ context.Context, id int64) (bool, error) {
	s.mu.Lock()
	if id != s.target {
		s.mu.Unlock()
		return false, nil
	}
	s.reads++
	read, gate := s.reads, s.gateRead
	s.mu.Unlock()

	if gate == read {
		s.gateOnce.Do(func() { close(s.blocked) })
		<-s.release
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listedReads < 0 {
		return false, nil
	}
	if s.failRead > 0 && read >= s.failRead {
		return false, errors.New("observation store unreachable")
	}
	return read > s.listedReads, nil
}

func TestPoolPresenceLookupPendingIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gateRead int
		failRead int
		inFlight bool
	}{
		{name: "idle connection, held past the reply budget", gateRead: 2},
		{name: "command running, held past the reply budget", gateRead: 2, inFlight: true},
		{name: "command running, lookup errors", failRead: 2, inFlight: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testPresenceLookupUnknown(t, tc.gateRead, tc.failRead, tc.inFlight)
		})
	}
}

// testPresenceLookupUnknown proves maintenance holds the entry when the lookup
// cannot answer. The identity the pool parked on is asserted where it surfaces
// (the checkout crossing case and the dead-busy checkout), not here, because
// maintenance deliberately discards it.
func testPresenceLookupUnknown(t *testing.T, gateRead, failRead int, inFlight bool) {
	t.Helper()
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	controlPeer := NewMockSSHServer(t, "root", "pass")
	defer controlPeer.Close()

	store := newGatedPresenceStore(991)
	pool := NewSSHClientPool(PoolConfig{
		KeepAlivePeriod: time.Hour,
		SweepInterval:   time.Hour,
		ReplyTimeout:    testReplyBudget,
	}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row := &models.Server{ID: 991, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	handle, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := handle.(*Client)
	if !ok {
		t.Fatalf("checkout returned %T, want the pool's own client", handle)
	}
	controlRow := &models.Server{ID: 992, Host: controlPeer.Host(), SSHPort: controlPeer.Port(), SSHUser: "root", SSHPass: "pass"}
	if _, err := pool.Get(ctx, controlRow); err != nil {
		t.Fatal(err)
	}

	var done chan error
	var release func()
	if inFlight {
		started, finish := make(chan struct{}), make(chan struct{})
		var finishOnce sync.Once
		release = func() { finishOnce.Do(func() { close(finish) }) }
		defer release()
		peer.SetCommandHandler("identity-held", func(string, []byte) (string, string, int) {
			close(started)
			<-finish
			return "finished", "", 0
		})
		done = make(chan error, 1)
		go func() {
			out, _, code, err := client.RunCommand(ctx, "identity-held")
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
	}

	// Validation's own read is answered; the read the request wrapper performs
	// for the keepalive is held (or fails) past the reply budget.
	store.arm(1, gateRead, failRead)
	pings, connects := peer.keepalives.Load(), peer.connects.Load()
	begin := time.Now()
	pool.pingAll()
	elapsed := time.Since(begin)
	t.Logf("in_flight=%t budget=%s hold=%s validation returned after %s", inFlight, testReplyBudget, testGateHold, elapsed)

	if gateRead > 0 {
		select {
		case <-store.blocked:
		default:
			t.Fatal("the request wrapper's presence read never started: the window was not exercised")
		}
		if elapsed < testReplyBudget {
			t.Fatalf("validation returned after %s, before the %s budget expired", elapsed, testReplyBudget)
		}
		if elapsed >= testGateHold {
			t.Fatalf("validation returned after %s, not while the read was still held (%s): the timer did not decide", elapsed, testGateHold)
		}
	}
	if pool.Len() != 2 {
		t.Errorf("pool length %d after an unanswered lookup, want 2: the entry was evicted", pool.Len())
	}
	if client.closed {
		t.Error("an unanswered lookup closed the connection")
	}
	if got := peer.keepalives.Load(); got != pings {
		t.Errorf("an unanswered lookup sent %d keepalive(s) to the server", got-pings)
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("an unanswered lookup opened %d connection(s)", got-connects)
	}

	// Release the held read (the row answers absent) and give the already
	// refused goroutine a bounded window to settle: it must still send nothing.
	store.releaseGate()
	settle := time.Now().Add(500 * time.Millisecond)
	for store.readCount() < 2 && time.Now().Before(settle) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := peer.keepalives.Load(); got != pings {
		t.Errorf("the released lookup sent %d keepalive(s) to the server", got-pings)
	}

	if inFlight {
		// The command was admitted before the lookup and must finish with its
		// exit status through a connection nobody closed.
		release()
		if err := <-done; err != nil {
			t.Fatalf("the unanswered lookup interrupted in-flight work: %v", err)
		}
	}
	if pool.Len() != 2 {
		t.Errorf("pool length %d after the command finished, want 2", pool.Len())
	}

	// Live control in the same run: the listed row still validates and serves.
	before := controlPeer.keepalives.Load()
	pool.pingAll()
	if controlPeer.keepalives.Load() == before {
		t.Error("the listed control sent no validation keepalive")
	}
	control, err := pool.Get(ctx, controlRow)
	if err != nil {
		t.Fatal(err)
	}
	runParkingCommand(t, ctx, control)
	if got := peer.connects.Load(); got != connects {
		t.Error("the control caused a connection to the measured server")
	}
}

func TestPoolCheckoutPresenceLookupPendingIsUnknown(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := newGatedPresenceStore(993)
	pool := NewSSHClientPool(PoolConfig{
		KeepAlivePeriod: time.Hour,
		SweepInterval:   time.Hour,
		ReplyTimeout:    testReplyBudget,
	}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row := &models.Server{ID: 993, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	if _, err := pool.Get(ctx, row); err != nil {
		t.Fatal(err)
	}
	// Admission and validation's own read answer; the wrapper's read is held
	// past the budget, so the checkout cannot obtain a completed answer.
	store.arm(2, 3, 0)
	connects := peer.connects.Load()
	begin := time.Now()
	client, err := pool.Get(ctx, row)
	elapsed := time.Since(begin)
	t.Logf("budget=%s hold=%s checkout returned after %s", testReplyBudget, testGateHold, elapsed)
	if !errors.Is(err, errLivenessUnknown) || client != nil {
		t.Fatalf("checkout = (%v, %v), want (nil, %v)", client, err, errLivenessUnknown)
	}
	if elapsed < testReplyBudget || elapsed >= testGateHold {
		t.Errorf("checkout returned after %s, want a return after the %s budget and before the read was released", elapsed, testReplyBudget)
	}
	if pool.Len() != 1 {
		t.Errorf("pool length %d after an unanswered checkout, want 1: the entry was evicted", pool.Len())
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("an unanswered checkout opened %d replacement connection(s)", got-connects)
	}
	store.releaseGate()

	// Released, the row answers absent: the entry is parked, never closed, and
	// checkout refuses it by the refusal identity.
	settle := time.Now().Add(time.Second)
	for store.readCount() < 3 && time.Now().Before(settle) {
		time.Sleep(2 * time.Millisecond)
	}
	if got, err := pool.Get(ctx, row); !errors.Is(err, ErrProviderAbsent) || got != nil {
		t.Fatalf("checkout after release = (%v, %v), want the refusal", got, err)
	}
	if pool.Len() != 1 {
		t.Errorf("the parked entry was not retained: pool length %d", pool.Len())
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("the parked entry opened %d connection(s)", got-connects)
	}
}

// A completed dead verdict still may not retire a connection that is carrying a
// command: the transport would take the command's exit status with it. A real
// transport cannot be observably dead while one of its commands still runs, so
// this case pins the maintenance decision itself: an entry whose transport is
// gone, with an operation held open on it.
func TestPoolMaintenanceDoesNotCloseInFlightConnection(t *testing.T) {
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour}, newMemoryHostKeyStore())
	defer pool.Close()

	client := NewClient(Config{}) // no transport: validation concludes dead
	inFlight := client.startOp()  // an operation is running on this connection
	key := "server:995:192.0.2.5:22:root"
	pool.mu.Lock()
	pool.conns[key] = &pooledEntry{client: client, key: key, lastActive: time.Now()}
	pool.mu.Unlock()

	pool.pingAll()
	if pool.Len() != 1 {
		t.Fatal("maintenance retired a connection while a command was in flight")
	}
	if client.closed {
		t.Fatal("maintenance closed a connection while a command was in flight")
	}
	if got, err := pool.Get(context.Background(), &models.Server{ID: 995, Host: "192.0.2.5", SSHPort: 22, SSHUser: "root"}); !errors.Is(err, errLivenessUnknown) || got != nil {
		t.Fatalf("checkout of a dead busy connection = (%v, %v), want the unknown identity", got, err)
	}
	if pool.Len() != 1 || client.closed {
		t.Fatal("the checkout retired or closed the connection it found busy")
	}

	// Idle again: the same dead connection is retired on the next cycle.
	inFlight()
	pool.pingAll()
	if pool.Len() != 0 {
		t.Fatal("an idle dead connection was not retired")
	}
	if !client.closed {
		t.Fatal("the retired connection was not closed")
	}
}
