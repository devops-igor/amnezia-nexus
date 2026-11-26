package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRetainedRawClient_RefusesNewChannelsAndRequests(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := &presenceStore{memoryHostKeyStore: newMemoryHostKeyStore()}
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := &models.Server{ID: 910, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	client, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	raw := client.GetUnderlyingClient()
	idle, err := raw.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	dial := raw.DialContext // retain the exact capability the scanner hands its workers
	store.set(true, nil)
	channels, requests := peer.channels.Load(), peer.keepalives.Load()
	commands := peer.commands.Load()
	if err := idle.Run("echo must-not-start"); !errors.Is(err, ErrProviderAbsent) {
		t.Errorf("preopened session accepted new command: %v", err)
	}
	if peer.commands.Load() != commands {
		t.Error("new exec request reached the peer after absence")
	}
	if session, err := raw.NewSession(); !errors.Is(err, ErrProviderAbsent) {
		if session != nil {
			_ = session.Close()
		}
		t.Errorf("new session = %v, want refusal", err)
	}
	if conn, err := dial(ctx, "tcp", "192.0.2.1:443"); !errors.Is(err, ErrProviderAbsent) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Errorf("retained scanner dial = %v, want refusal", err)
	}
	if _, _, err := raw.SendRequest("keepalive@openssh.com", true, nil); !errors.Is(err, ErrProviderAbsent) {
		t.Errorf("retained request = %v, want refusal", err)
	}
	if peer.channels.Load() != channels || peer.keepalives.Load() != requests {
		t.Errorf("absent work reached peer: channels %d -> %d, requests %d -> %d", channels, peer.channels.Load(), requests, peer.keepalives.Load())
	}
	store.set(false, nil)
	if _, _, err := raw.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(ctx, "tcp", "192.0.2.1:443"); err == nil || errors.Is(err, ErrProviderAbsent) {
		t.Errorf("listed scanner control = %v", err)
	}
	if peer.channels.Load() != channels+1 || peer.keepalives.Load() != requests+1 {
		t.Error("listed controls did not reach the peer")
	}
	runParkingCommand(t, ctx, client)
}
