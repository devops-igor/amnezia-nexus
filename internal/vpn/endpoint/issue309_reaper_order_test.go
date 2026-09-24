package endpoint

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestTimeoutHookRunsBeforeTransportKeyPruning(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager(nil, nil)
	el, err := NewListener(ListenerConfig{ListenPort: testFreePort(t), IdleTimeout: time.Minute}, nil, nil, nil, sm, nil)
	if err != nil {
		t.Fatal(err)
	}
	const peer = "peer"
	sess, err := sm.CreateSession(ctx, "user", peer, "10.100.0.3", 1, "conn", 1)
	if err != nil {
		t.Fatal(err)
	}
	el.StoreTransportKeysForTest(peer, &TransportKeys{SendKey: make([]byte, 32), RecvKey: make([]byte, 32)})
	sm.SetSessionLastSeen(peer, time.Now().Add(-2*time.Minute))
	var hooked bool
	el.SetSessionReaperHook(func(_ context.Context, reaped *models.VPNSession) {
		hooked = true
		if reaped.ID != sess.ID {
			t.Errorf("hook received session %s, want %s", reaped.ID, sess.ID)
		}
		if _, ok := el.TransportKeysFor(peer); !ok {
			t.Error("transport keys were pruned before the route retirement hook")
		}
	})
	if _, err := el.SweepTimedOutSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if !hooked {
		t.Fatal("reaper hook was not called")
	}
	if _, ok := el.TransportKeysFor(peer); ok {
		t.Fatal("transport keys survived completed timeout teardown")
	}
}
