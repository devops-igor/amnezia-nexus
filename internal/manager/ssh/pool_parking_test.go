package ssh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type presenceStore struct {
	*memoryHostKeyStore
	mu       sync.Mutex
	absent   bool
	listedID int64
	err      error
}

func (s *presenceStore) IsServerProviderAbsent(_ context.Context, id int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.absent && (s.listedID == 0 || id != s.listedID), s.err
}

func (s *presenceStore) set(absent bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.absent, s.err = absent, err
}

func TestSSHClientPool_ParksAbsentConnection(t *testing.T) {
	for _, warm := range []bool{false, true} {
		name := "cold"
		if warm {
			name = "warm"
		}
		t.Run(name, func(t *testing.T) { testPoolParking(t, warm) })
	}
}

func testPoolParking(t *testing.T, warm bool) {
	t.Helper()
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := &presenceStore{memoryHostKeyStore: newMemoryHostKeyStore(), listedID: 802}
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	row := &models.Server{ID: 800, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	var cached SSHClient
	if warm {
		var err error
		cached, err = pool.Get(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		runParkingCommand(t, ctx, cached)
	}
	store.set(true, nil)
	commands, pings := peer.commands.Load(), peer.keepalives.Load()
	// The row/config deliberately predates absence; the durable observation wins.
	pool.pingAll()
	if warm {
		if _, _, _, err := cached.RunCommand(ctx, "echo must-not-run"); !errors.Is(err, ErrProviderAbsent) {
			t.Errorf("retained handle accepted a new command: %v", err)
		}
	}
	client, err := pool.Get(ctx, row)
	if !errors.Is(err, ErrProviderAbsent) || client != nil {
		t.Errorf("absent checkout = (%v, %v), want (nil, ErrProviderAbsent)", client, err)
		if client != nil {
			runParkingCommand(t, ctx, client)
		}
	}
	client, err = pool.GetWithConfig(ctx, Config{Host: row.Host, Port: row.SSHPort, User: row.SSHUser, Password: row.SSHPass, ServerID: &row.ID, Store: newMemoryHostKeyStore()})
	if !errors.Is(err, ErrProviderAbsent) || client != nil {
		t.Errorf("absent config checkout = (%v, %v), want refusal", client, err)
	}
	if peer.commands.Load() != commands || peer.keepalives.Load() != pings {
		t.Errorf("refusal sent traffic: commands %d -> %d; keepalives %d -> %d", commands, peer.commands.Load(), pings, peer.keepalives.Load())
	}
	wantLen := 0
	if warm {
		wantLen = 1
	}
	if pool.Len() != wantLen {
		t.Errorf("parked pool length = %d, want %d", pool.Len(), wantLen)
	}
	// A different listed row still works while the original remains absent.
	livePeer := NewMockSSHServer(t, "root", "pass")
	defer livePeer.Close()
	controlRow := &models.Server{ID: 802, Host: livePeer.Host(), SSHPort: livePeer.Port(), SSHUser: "root", SSHPass: "pass"}
	control, err := pool.Get(ctx, controlRow)
	if err != nil {
		t.Fatal(err)
	}
	runParkingCommand(t, ctx, control)
	pool.pingAll()
	if livePeer.commands.Load() != 1 || livePeer.keepalives.Load() == 0 {
		t.Error("listed control did not execute and ping while absent row was parked")
	}
	if peer.commands.Load() != commands || peer.keepalives.Load() != pings {
		t.Error("live control caused traffic to the absent row")
	}
	store.set(false, nil)
	live, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	if warm && live != cached {
		t.Error("reappearance lost the parked connection")
	}
	runParkingCommand(t, ctx, live)
	pool.pingAll()
	if peer.keepalives.Load() <= pings {
		t.Error("listed control sent no validation/keepalive")
	}
	if peer.commands.Load() != commands+1 {
		t.Error("listed control did not execute exactly one command")
	}
	store.set(false, errors.New("observation unavailable"))
	pings = peer.keepalives.Load()
	pool.pingAll()
	if got, err := pool.Get(ctx, row); err == nil || got != nil {
		t.Error("failed observation allowed checkout")
	}
	if peer.keepalives.Load() != pings {
		t.Error("failed observation allowed a ping")
	}
}

func runParkingCommand(t *testing.T, ctx context.Context, client SSHClient) {
	t.Helper()
	out, _, code, err := client.RunCommand(ctx, "echo parking-control")
	if err != nil || code != 0 || out != "parking-control" {
		t.Fatalf("command = (%q, %d, %v)", out, code, err)
	}
}

func TestSSHClientPool_ParkingPreservesInFlightCommand(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := &presenceStore{memoryHostKeyStore: newMemoryHostKeyStore(), listedID: 802}
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	row := &models.Server{ID: 801, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	client, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	started, finish := make(chan struct{}), make(chan struct{})
	peer.SetCommandHandler("in-flight", func(string, []byte) (string, string, int) {
		close(started)
		<-finish
		return "finished", "", 0
	})
	done := make(chan error, 1)
	go func() {
		out, _, code, err := client.RunCommand(ctx, "in-flight")
		if err == nil && (out != "finished" || code != 0) {
			err = errors.New("in-flight result changed")
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	store.set(true, nil)
	_, checkoutErr := pool.Get(ctx, row)
	pool.pingAll()
	close(finish)
	if !errors.Is(checkoutErr, ErrProviderAbsent) {
		t.Errorf("checkout = %v", checkoutErr)
	}
	if err := <-done; err != nil {
		t.Fatalf("parking interrupted work: %v", err)
	}
}
