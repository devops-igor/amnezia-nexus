package handlers

// Regression coverage for issue #391 round 4b, finding 4: a caller must be able
// to learn that the runtime enforcement of its durable change FAILED.
//
// The post-commit notification is deliberately asynchronous, so the durable
// call cannot report the runtime outcome itself. These tests pin that the
// handler still answers runtime_sync_failed when enforcement genuinely fails
// and success when it genuinely succeeds.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// convergingPeerSyncListener models the production post-commit contract of
// issue #391 round 4a finding 2 and round 4b finding 4 together: the
// notification is a non-blocking enqueue that reports no runtime error and runs
// no device I/O on the committing goroutine, while the enforcement outcome is
// confirmed separately through database.PeerRuntimeConvergence, on the
// caller's goroutine, after the commit returned.
//
// failEnforcement makes the asynchronous pass fail, exactly as the production
// peerSynchronizer does when the upstream device refuses the change.
type convergingPeerSyncListener struct {
	mu              sync.Mutex
	enqueued        int
	failEnforcement bool
	enqueuedCh      chan struct{}
}

// ReconcilePeers is the notification entry point: it records the request and
// returns immediately. It never reconciles inline and never blocks, which is
// what lets a commit run under Service.mu without deadlocking.
func (l *convergingPeerSyncListener) ReconcilePeers(context.Context) error {
	l.mu.Lock()
	l.enqueued++
	l.mu.Unlock()
	select {
	case l.enqueuedCh <- struct{}{}:
	default:
	}
	return nil
}

func (l *convergingPeerSyncListener) ValidatePortalConfig(*models.VPNConfig) error { return nil }

// AwaitPeerRuntimeSync is the caller-visible half. It waits for the enforcement
// the caller was told about, so the handler learns the outcome on its own
// goroutine without ever holding a runtime lock.
func (l *convergingPeerSyncListener) AwaitPeerRuntimeSync(ctx context.Context) error {
	if err := l.waitEnqueued(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	fail := l.failEnforcement
	l.mu.Unlock()
	if fail {
		return database.ErrPeerRuntimeSync
	}
	return nil
}

// waitEnqueued blocks until at least one notification has been enqueued, so the
// convergence wait is deterministic rather than a race with the worker.
func (l *convergingPeerSyncListener) waitEnqueued(ctx context.Context) error {
	l.mu.Lock()
	already := l.enqueued > 0
	l.mu.Unlock()
	if already {
		return nil
	}
	select {
	case <-l.enqueuedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("no enforcement was enqueued")
	}
}

func (l *convergingPeerSyncListener) enqueueCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enqueued
}

// newPeerSyncTestFixture builds a handler set whose database has a
// convergingPeerSyncListener installed, plus one deletable portal connection
// owned by a regular user.
func newPeerSyncTestFixture(t *testing.T, failEnforcement bool) (*Handlers, *database.DB, *models.SessionData, *models.UserConnection, *convergingPeerSyncListener) {
	t.Helper()
	h, db, _ := setupTestHandlersWithMockSSH(t, &testMockSSHClient{})
	ctx := t.Context()
	user := &models.User{ID: "u-sync-converge", Username: "syncconverge", Role: models.RoleUser, Enabled: true}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	conn := &models.UserConnection{
		ID: "conn-sync-converge", UserID: user.ID, ServerID: 0, Protocol: "awg",
		ClientID: "sync-converge-peer", Name: "To delete",
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	listener := &convergingPeerSyncListener{failEnforcement: failEnforcement, enqueuedCh: make(chan struct{}, 64)}
	unsubscribe, err := db.SubscribePeerChanges(listener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unsubscribe)
	sess := &models.SessionData{UserID: user.ID, Role: models.RoleUser}
	return h, db, sess, conn, listener
}

// deleteConnection runs the user-facing connection delete, which is one of the
// call sites that must report a failed enforcement to its caller.
func deleteConnection(t *testing.T, h *Handlers, sess *models.SessionData, connID string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Post("/api/connections/{connection_id}/delete", h.UserDeleteConnectionHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/connections/"+connID+"/delete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req.WithContext(middleware.WithSession(req.Context(), sess)))
	return w
}

// TestConnectionDeleteReportsRuntimeEnforcementFailure is the finding-4
// regression. Before the fix the async path discarded the reconcile result, so
// this exact scenario answered HTTP 200: the durable delete was reported as
// complete while the peer's live access had not been withdrawn.
func TestConnectionDeleteReportsRuntimeEnforcementFailure(t *testing.T) {
	h, db, sess, conn, listener := newPeerSyncTestFixture(t, true)

	w := deleteConnection(t, h, sess, conn.ID)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failed enforcement reported as %d, want 500: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "runtime_sync_failed") {
		t.Fatalf("response does not report runtime_sync_failed: %s", w.Body.String())
	}
	assertErrorCode(t, w, "runtime_sync_failed")
	// The durable change itself is still committed: the caller is told the
	// runtime did not converge, not that the save failed.
	if stored, err := db.GetConnection(t.Context(), conn.ID); err != nil || stored != nil {
		t.Fatalf("durable delete was rolled back: %+v err=%v", stored, err)
	}
	// And the enforcement really was requested, not skipped.
	if listener.enqueueCount() == 0 {
		t.Fatal("no enforcement was enqueued for the durable delete")
	}
}

// TestConnectionDeleteReportsRuntimeEnforcementSuccess is the other half of the
// same contract: a genuinely successful enforcement must still answer success.
// A fix that simply always failed would pass the test above and break real
// operation, so both directions are pinned.
func TestConnectionDeleteReportsRuntimeEnforcementSuccess(t *testing.T) {
	h, db, sess, conn, listener := newPeerSyncTestFixture(t, false)

	w := deleteConnection(t, h, sess, conn.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("successful enforcement reported as %d, want 200: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "runtime_sync_failed") {
		t.Fatalf("successful enforcement produced a runtime_sync_failed envelope: %s", w.Body.String())
	}
	if stored, err := db.GetConnection(t.Context(), conn.ID); err != nil || stored != nil {
		t.Fatalf("durable delete did not commit: %+v err=%v", stored, err)
	}
	if listener.enqueueCount() == 0 {
		t.Fatal("no enforcement was enqueued for the durable delete")
	}
}

// TestConnectionDeleteWithoutListenerReportsSuccess pins that the caller-visible
// confirmation is additive: with no peer synchronizer installed there is no
// asynchronous enforcement outstanding, so the handler must not invent a
// failure or block waiting for one.
func TestConnectionDeleteWithoutListenerReportsSuccess(t *testing.T) {
	h, db, _ := setupTestHandlersWithMockSSH(t, &testMockSSHClient{})
	ctx := t.Context()
	user := &models.User{ID: "u-no-listener", Username: "nolistener", Role: models.RoleUser, Enabled: true}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	conn := &models.UserConnection{
		ID: "conn-no-listener", UserID: user.ID, ServerID: 0, Protocol: "awg",
		ClientID: "no-listener-peer", Name: "To delete",
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	sess := &models.SessionData{UserID: user.ID, Role: models.RoleUser}

	w := deleteConnection(t, h, sess, conn.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("delete without a peer synchronizer reported %d, want 200: %s", w.Code, w.Body.String())
	}
	if stored, err := db.GetConnection(ctx, conn.ID); err != nil || stored != nil {
		t.Fatalf("durable delete did not commit: %+v err=%v", stored, err)
	}
}

// TestToggleUserReportsRuntimeEnforcementFailure covers a second call site with
// a different durable shape (a user-level access change rather than a single
// connection), because the confirmation is added per handler and each one has
// to be covered.
func TestToggleUserReportsRuntimeEnforcementFailure(t *testing.T) {
	h, db, _ := setupTestHandlersWithMockSSH(t, &testMockSSHClient{})
	ctx := t.Context()
	user := &models.User{ID: "u-toggle-converge", Username: "toggleconverge", Role: models.RoleAdmin, Enabled: true}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-toggle-converge", UserID: user.ID, ServerID: 0, Protocol: "awg",
		ClientID: "toggle-converge-peer", Name: "Portal peer",
	}); err != nil {
		t.Fatal(err)
	}
	listener := &convergingPeerSyncListener{failEnforcement: true, enqueuedCh: make(chan struct{}, 64)}
	unsubscribe, err := db.SubscribePeerChanges(listener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unsubscribe)

	router := chi.NewRouter()
	router.Post("/api/users/{user_id}/toggle", h.ToggleUserHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+user.ID+"/toggle",
		strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	sess := &models.SessionData{UserID: "admin", Role: models.RoleAdmin}
	router.ServeHTTP(w, req.WithContext(middleware.WithSession(req.Context(), sess)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failed user-access enforcement reported as %d, want 500: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w, "runtime_sync_failed")
	// The access change is durable even though its enforcement failed: the
	// operator sees a committed revocation that the runtime has not applied.
	stored, err := db.GetUser(ctx, user.ID)
	if err != nil || stored == nil {
		t.Fatalf("user row missing: %v", err)
	}
	if stored.Enabled {
		t.Fatal("durable disable did not commit")
	}
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	var payload struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v (body %s)", err, w.Body.String())
	}
	if payload.Error != want {
		t.Fatalf("error code %q, want %q (body %s)", payload.Error, want, w.Body.String())
	}
}
