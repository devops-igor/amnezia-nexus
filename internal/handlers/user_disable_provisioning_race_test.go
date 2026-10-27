package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/userops"
)

// remoteNode is a fake remote credential store shared by the VLESS/Naive mock managers.
type remoteNode struct {
	mu      sync.Mutex
	clients map[string]bool
}

func (n *remoteNode) set(id string, on bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if on {
		n.clients[id] = true
	} else {
		delete(n.clients, id)
	}
}

func (n *remoteNode) active() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.clients)
}

type provisioningRig struct {
	h      *Handlers
	node   *remoteNode
	userID string
	sID    int64
	proto  string
}

// newProvisioningRig registers a mock manager for proto whose AddClient runs onAdd
// (while the credential is "in flight") before the credential becomes active remotely.
func newProvisioningRig(t *testing.T, proto string, onAdd func()) *provisioningRig {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()
	node := &remoteNode{clients: map[string]bool{}}
	h.registry.Register(&mockProtocolManager{
		protocol: proto,
		addClientFn: func(_ context.Context, _ *models.Server, _ map[string]any) (map[string]any, error) {
			onAdd()
			node.set("cid-"+proto, true)
			return map[string]any{"client_id": "cid-" + proto, "config": "cfg"}, nil
		},
		removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
			node.set(clientID, false)
			return nil
		},
	})
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "race", Host: "192.168.1.96", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{proto: map[string]any{"installed": true}},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	_ = db.UpdateServerReachability(ctx, sID, models.ReachabilityOnline)
	u := &models.User{ID: "race-user", Username: "raceuser", PasswordHash: "hash", Role: models.RoleUser, Enabled: true, CreatedAt: time.Now()}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return &provisioningRig{h: h, node: node, userID: u.ID, sID: sID, proto: proto}
}

func (r *provisioningRig) addConnection(t *testing.T) int {
	t.Helper()
	body, _ := json.Marshal(models.MyAddConnectionRequest{ServerID: r.sID, Protocol: r.proto, Name: "inflight"})
	req := httptest.NewRequest(http.MethodPost, "/api/connections/add", bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: r.userID, Role: models.RoleUser}))
	w := httptest.NewRecorder()
	setupFullConnectionsRouter(r.h).ServeHTTP(w, req)
	return w.Code
}

func (r *provisioningRig) assertRevoked(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	if u, _ := r.h.db.GetUser(ctx, r.userID); u == nil || u.Enabled {
		t.Error("user must be disabled")
	}
	if n := r.node.active(); n != 0 {
		t.Errorf("%d credential(s) still active on the remote node", n)
	}
	if conns, _ := r.h.db.GetConnectionsByUserID(ctx, r.userID); len(conns) != 0 {
		t.Errorf("disabled user keeps %d connection row(s)", len(conns))
	}
}

// TestDisableWaitsForInFlightProvisioning holds AddClient open, disables the user
// concurrently (HTTP toggle or userops) and proves the disable serializes behind the
// admission and then revokes the freshly created credential.
func TestDisableWaitsForInFlightProvisioning(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		for _, via := range []string{"http", "userops"} {
			t.Run(proto+"/"+via, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				rig := newProvisioningRig(t, proto, func() {
					close(entered)
					<-release
				})

				addCode := make(chan int, 1)
				go func() { addCode <- rig.addConnection(t) }()
				<-entered

				disabled := make(chan error, 1)
				go func() {
					if via == "userops" {
						_, err := userops.New(rig.h.db, rig.h.registry).ToggleUser(context.Background(), rig.userID, false)
						disabled <- err
						return
					}
					req := httptest.NewRequest(http.MethodPost, "/api/users/"+rig.userID+"/toggle", bytes.NewReader([]byte(`{"enabled":false}`)))
					w := httptest.NewRecorder()
					setupFullUsersRouter(rig.h).ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						disabled <- fmt.Errorf("toggle status %d", w.Code)
						return
					}
					disabled <- nil
				}()

				select {
				case <-disabled:
					t.Fatal("disable completed while credential provisioning was still in flight")
				case <-time.After(150 * time.Millisecond):
				}

				close(release)
				if code := <-addCode; code != http.StatusOK {
					t.Fatalf("in-flight add: expected 200 (it won the lock), got %d", code)
				}
				if err := <-disabled; err != nil {
					t.Fatalf("disable failed: %v", err)
				}
				rig.assertRevoked(t)
			})
		}
	}
}

// TestInFlightProvisioningCompensatesWhenUserDisabled covers a disable that commits
// without holding the user lock: admission must notice, revoke the remote credential
// and refuse to persist a connection row.
func TestInFlightProvisioningCompensatesWhenUserDisabled(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			var rig *provisioningRig
			rig = newProvisioningRig(t, proto, func() {
				_, _ = rig.h.db.UpdateUser(context.Background(), rig.userID, map[string]any{"enabled": false})
			})
			if code := rig.addConnection(t); code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", code)
			}
			rig.assertRevoked(t)
		})
	}
}
