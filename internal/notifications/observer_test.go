package notifications

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func observerTestEvent(t *testing.T, svc *Service, eventType string) models.NotificationHistoryItem {
	t.Helper()
	history, err := svc.db.ListNotificationHistory(context.Background(), 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	for _, item := range history {
		if item.Event.Type == eventType {
			return item
		}
	}
	t.Fatalf("no %q event in history (%d events)", eventType, len(history))
	return models.NotificationHistoryItem{}
}

func TestObserverServerReachabilityTransitions(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "alpha", Host: "198.51.100.10"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
		t.Fatalf("set online: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline observe: %v", err)
	}
	history, _ := db.ListNotificationHistory(ctx, 50)
	if len(history) != 0 {
		t.Fatalf("baseline produced %d events, want 0", len(history))
	}

	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOffline); err != nil {
		t.Fatalf("set offline: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("offline observe: %v", err)
	}
	offline := observerTestEvent(t, notifier, "server.reachability.offline")
	if offline.Event.Severity != models.NotificationSeverityCritical || offline.Event.Transition != "online->offline" {
		t.Fatalf("offline event = %#v", offline.Event)
	}

	// A repeated observation of the same authoritative state is not a new event.
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("repeat observe: %v", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 50)
	if len(history) != 1 {
		t.Fatalf("repeat observation produced %d events, want 1", len(history))
	}

	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
		t.Fatalf("set online again: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("recovery observe: %v", err)
	}
	recovery := observerTestEvent(t, notifier, "server.reachability.online")
	if !recovery.Event.Recovery || recovery.Event.Transition != "offline->online" {
		t.Fatalf("recovery event = %#v", recovery.Event)
	}

	// Monitoring uncertainty is never a confirmed outage or recovery.
	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityUnknown); err != nil {
		t.Fatalf("set unknown: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("unknown observe: %v", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 50)
	if len(history) != 2 {
		t.Fatalf("unknown state produced %d events, want 2", len(history))
	}
}

func TestObserverTransitionFlowsToControlledReceiver(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token"))
	notifier := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, notifier)
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "alpha", Host: "198.51.100.50"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
		t.Fatalf("set online: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOffline); err != nil {
		t.Fatalf("set offline: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("offline observe: %v", err)
	}
	select {
	case req := <-requests:
		if req.Body["title"] != "Server alpha is offline" {
			t.Fatalf("title = %v", req.Body["title"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer transition did not reach the controlled receiver")
	}
}

func TestObserverBackendHealthTransitions(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "backend-host", Host: "198.51.100.20"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg0", Protocol: models.ProtocolAWG,
		PublicKey: "pub", PrivateKey: "priv", Endpoint: "198.51.100.20:51820",
		Enabled: true, Status: models.TunnelStatusActive,
	})
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline observe: %v", err)
	}
	if history, _ := db.ListNotificationHistory(ctx, 50); len(history) != 0 {
		t.Fatalf("baseline produced %d events", len(history))
	}

	version := int64(1)
	swap := func(expectedStatus, expectedReason, nextStatus, nextReason string) {
		t.Helper()
		ok, err := db.CompareAndSwapTunnelStatus(ctx, tunnelID, expectedStatus, expectedReason, version, nextStatus, nextReason, 0)
		if err != nil || !ok {
			t.Fatalf("swap %s->%s ok=%v err=%v", expectedStatus, nextStatus, ok, err)
		}
		version++
	}

	swap(models.TunnelStatusActive, "", models.TunnelStatusHandshakeBlocked, "")
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("blocked observe: %v", err)
	}
	blocked := observerTestEvent(t, notifier, "backend.handshake_blocked")
	if blocked.Event.Severity != models.NotificationSeverityWarning {
		t.Fatalf("blocked severity = %q", blocked.Event.Severity)
	}

	swap(models.TunnelStatusHandshakeBlocked, "", models.TunnelStatusActive, "")
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("recovery observe: %v", err)
	}
	if !observerTestEvent(t, notifier, "backend.recovered").Event.Recovery {
		t.Fatal("backend recovery was not marked as recovery")
	}

	swap(models.TunnelStatusActive, "", models.TunnelStatusDegraded, "")
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("degraded observe: %v", err)
	}
	if observerTestEvent(t, notifier, "backend.degraded").Event.Severity != models.NotificationSeverityWarning {
		t.Fatal("degraded backend must be a warning")
	}
	swap(models.TunnelStatusDegraded, "", models.TunnelStatusActive, "")
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("degraded recovery observe: %v", err)
	}

	swap(models.TunnelStatusActive, "", models.TunnelStatusDisabled, models.DisableReasonHealth)
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("health disable observe: %v", err)
	}
	disabled := observerTestEvent(t, notifier, "backend.health_disabled")
	if disabled.Event.Severity != models.NotificationSeverityCritical {
		t.Fatalf("health disable severity = %q", disabled.Event.Severity)
	}
}

func TestObserverAdministratorDisableIsNotAnIncident(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, _ := db.CreateServer(ctx, &models.Server{Name: "backend-host", Host: "198.51.100.30"})
	tunnelID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg1", Protocol: models.ProtocolAWG,
		PublicKey: "pub", PrivateKey: "priv", Endpoint: "198.51.100.30:51820",
		Enabled: true, Status: models.TunnelStatusActive,
	})
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := db.UpdateBackendTunnelEnabled(ctx, tunnelID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("admin disable: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("disable observe: %v", err)
	}
	// Re-enable without a fresh health transition; intentional actions must not
	// be reported as failures or recoveries.
	if err := db.UpdateBackendTunnelEnabled(ctx, tunnelID, true, models.DisableReasonNone); err != nil {
		t.Fatalf("admin enable: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("enable observe: %v", err)
	}
	history, _ := db.ListNotificationHistory(ctx, 50)
	if len(history) != 0 {
		t.Fatalf("administrative disable/enable produced %d events, want 0", len(history))
	}
}

func TestObserverProvisioningTransitions(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	order := &models.GigahostOrder{
		OrderID: "order-100", Status: "pending",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := db.InsertGigahostOrder(ctx, order); err != nil {
		t.Fatalf("insert order: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	order.Status = "failed"
	if err := db.UpdateGigahostOrder(ctx, order); err != nil {
		t.Fatalf("fail order: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("failed observe: %v", err)
	}
	failed := observerTestEvent(t, notifier, "order.failed")
	if failed.Event.Severity != models.NotificationSeverityWarning {
		t.Fatalf("order failure severity = %q", failed.Event.Severity)
	}

	order.Status = "unknown"
	if err := db.UpdateGigahostOrder(ctx, order); err != nil {
		t.Fatalf("unknown order: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("unknown observe: %v", err)
	}
	if observerTestEvent(t, notifier, "order.outcome_unknown").Event.Severity != models.NotificationSeverityCritical {
		t.Fatal("ambiguous order outcome must be critical")
	}

	intent := &models.GigahostSetupIntent{
		OrderID: "order-100", State: models.SetupStatePending,
		Protocol: models.ProtocolAWG, Port: "51820", CredentialMode: models.SetupCredentialManaged,
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("create intent: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("intent baseline: %v", err)
	}

	transitionIntent := func(nextState, step string, mismatch bool) {
		t.Helper()
		current, found, err := db.GetGigahostSetupIntent(ctx, intent.OrderID)
		if err != nil || !found {
			t.Fatalf("get intent found=%v err=%v", found, err)
		}
		current.State = nextState
		current.Step = step
		current.HostMismatch = mismatch
		ok, err := db.TransitionGigahostSetupIntent(ctx, current, []string{intent.State})
		if err != nil || !ok {
			t.Fatalf("transition to %s ok=%v err=%v", nextState, ok, err)
		}
		intent.State = nextState
	}

	transitionIntent(models.SetupStateAwaitingCredentials, "", false)
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("awaiting credentials observe: %v", err)
	}
	if observerTestEvent(t, notifier, "setup.awaiting_credentials").Event.Severity != models.NotificationSeverityWarning {
		t.Fatal("awaiting credentials must be a warning")
	}

	transitionIntent(models.SetupStateInstallPaused, models.SetupPhaseInstalled, false)
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("paused observe: %v", err)
	}
	if observerTestEvent(t, notifier, "setup.paused").Event.Severity != models.NotificationSeverityCritical {
		t.Fatal("paused setup must be critical")
	}

	transitionIntent(models.SetupStateReady, "", false)
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("ready observe: %v", err)
	}
	if !observerTestEvent(t, notifier, "setup.ready").Event.Recovery {
		t.Fatal("setup completion after a pause must be a recovery")
	}

	transitionIntent(models.SetupStateCanceled, "", false)
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("canceled observe: %v", err)
	}
	canceled := observerTestEvent(t, notifier, "setup.canceled")
	if canceled.Delivery.Status != models.NotificationDeliverySuppressed || canceled.Delivery.LastError != "history_only" {
		t.Fatalf("cancellation must be history-only, got %#v", canceled.Delivery)
	}
}

func TestObserverAnnouncesNewOrderFirstObservedTerminal(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	insertOrder := func(orderID, status string, createdAt time.Time) {
		t.Helper()
		if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
			OrderID: orderID, Status: status, CreatedAt: createdAt, UpdatedAt: createdAt,
		}); err != nil {
			t.Fatalf("insert order %s: %v", orderID, err)
		}
	}
	insertOrder("historical-failed", "failed", observer.startedAt.Add(-time.Hour))
	insertOrder("historical-unknown", "unknown", observer.startedAt.Add(-2*time.Hour))
	insertOrder("new-failed", "failed", observer.startedAt.Add(time.Second))
	insertOrder("new-unknown", "unknown", observer.startedAt.Add(2*time.Second))

	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("observe: %v", err)
	}
	history, err := db.ListNotificationHistory(ctx, 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var failed, unknown []string
	for _, item := range history {
		switch item.Event.Type {
		case "order.failed":
			failed = append(failed, item.Event.EntityID)
		case "order.outcome_unknown":
			unknown = append(unknown, item.Event.EntityID)
		}
	}
	if len(failed) != 1 || failed[0] != "new-failed" {
		t.Fatalf("order.failed events = %v, want exactly new-failed", failed)
	}
	if len(unknown) != 1 || unknown[0] != "new-unknown" {
		t.Fatalf("order.outcome_unknown events = %v, want exactly new-unknown", unknown)
	}

	// A restart baselines historical rows instead of replaying their incidents,
	// but a newly created order after the durable baseline is still announced.
	insertOrder("post-restart-failed", "failed", observer.startedAt.Add(3*time.Second))
	restarted := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	if err := restarted.ObserveOnce(ctx); err != nil {
		t.Fatalf("restart observe: %v", err)
	}
	afterRestart, _ := db.ListNotificationHistory(ctx, 50)
	if len(afterRestart) != len(history)+1 {
		t.Fatalf("restart events = %d, want one new post-baseline order", len(afterRestart))
	}
	var postRestartFailed int
	for _, item := range afterRestart {
		if item.Event.Type == "order.failed" && item.Event.EntityID == "post-restart-failed" {
			postRestartFailed++
		}
	}
	if postRestartFailed != 1 {
		t.Fatalf("post-restart failed order events = %d, want 1", postRestartFailed)
	}

	// A fresh panel seeing only a historical failed order stays quiet.
	freshDB := openNotificationDB(t)
	freshNotifier := NewService(freshDB, Options{})
	freshObserver := NewObserver(freshDB, freshNotifier, ObserverOptions{Now: time.Now})
	if err := freshDB.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: "pre-existing", Status: "failed",
		CreatedAt: freshObserver.startedAt.Add(-time.Hour),
		UpdatedAt: freshObserver.startedAt.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("insert pre-existing order: %v", err)
	}
	if err := freshObserver.ObserveOnce(ctx); err != nil {
		t.Fatalf("fresh observe: %v", err)
	}
	if events, _ := freshDB.ListNotificationHistory(ctx, 10); len(events) != 0 {
		t.Fatalf("historical failed order replayed %d events", len(events))
	}
}

func TestObserverHostMismatchIsCritical(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	intent := &models.GigahostSetupIntent{
		OrderID: "order-200", State: models.SetupStateReadyForSetup,
		Protocol: models.ProtocolAWG, Port: "51820", CredentialMode: models.SetupCredentialManaged,
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("create intent: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	current, found, _ := db.GetGigahostSetupIntent(ctx, intent.OrderID)
	if !found {
		t.Fatal("intent disappeared")
	}
	current.HostMismatch = true
	ok, err := db.TransitionGigahostSetupIntent(ctx, current, []string{models.SetupStateReadyForSetup})
	if err != nil || !ok {
		t.Fatalf("mismatch transition ok=%v err=%v", ok, err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("mismatch observe: %v", err)
	}
	if observerTestEvent(t, notifier, "setup.host_mismatch").Event.Severity != models.NotificationSeverityCritical {
		t.Fatal("host identity mismatch must be critical")
	}
}

func TestObserverProtocolCapacityIgnoresStartupConnecting(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, _ := db.CreateServer(ctx, &models.Server{Name: "backend-host", Host: "198.51.100.41"})
	tunnelID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg3", Protocol: models.ProtocolAWG,
		PublicKey: "pub", PrivateKey: "priv", Endpoint: "198.51.100.41:51820",
		Enabled: true, Status: models.TunnelStatusActive,
	})
	userID, err := db.CreateUser(ctx, &models.User{Username: "startup-user", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: serverID, Protocol: models.ProtocolAWG, ClientID: "client-startup",
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	ok, err := db.CompareAndSwapTunnelStatus(ctx, tunnelID, models.TunnelStatusActive, "", 1, models.TunnelStatusConnecting, "", 0)
	if err != nil || !ok {
		t.Fatalf("set connecting: ok=%v err=%v", ok, err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("connecting observe: %v", err)
	}
	history, _ := db.ListNotificationHistory(ctx, 50)
	if len(history) != 0 {
		t.Fatalf("startup connecting produced %d notifications", len(history))
	}
	if _, err := db.CompareAndSwapTunnelStatus(ctx, tunnelID, models.TunnelStatusConnecting, "", 2, models.TunnelStatusActive, "", 0); err != nil {
		t.Fatalf("restore active: %v", err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("active observe: %v", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 50)
	if len(history) != 0 {
		t.Fatalf("settling back to active produced %d notifications", len(history))
	}
}

func TestObserverProtocolCapacityIsAggregated(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Now: time.Now})
	ctx := context.Background()

	serverID, _ := db.CreateServer(ctx, &models.Server{Name: "backend-host", Host: "198.51.100.40"})
	tunnelID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg2", Protocol: models.ProtocolAWG,
		PublicKey: "pub", PrivateKey: "priv", Endpoint: "198.51.100.40:51820",
		Enabled: true, Status: models.TunnelStatusActive,
	})
	userID, err := db.CreateUser(ctx, &models.User{Username: "observer-user", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: serverID, Protocol: models.ProtocolAWG, ClientID: "client-1",
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	ok, err := db.CompareAndSwapTunnelStatus(ctx, tunnelID, models.TunnelStatusActive, "", 1, models.TunnelStatusHandshakeBlocked, "", 0)
	if err != nil || !ok {
		t.Fatalf("block tunnel: ok=%v err=%v", ok, err)
	}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("unavailable observe: %v", err)
	}
	unavailable := observerTestEvent(t, notifier, "protocol.capacity_unavailable")
	if unavailable.Event.Severity != models.NotificationSeverityCritical {
		t.Fatalf("aggregate severity = %q", unavailable.Event.Severity)
	}
	history, _ := db.ListNotificationHistory(ctx, 50)
	var aggregateCount int
	for _, item := range history {
		if item.Event.Type == "protocol.capacity_unavailable" {
			aggregateCount++
		}
	}
	if aggregateCount != 1 {
		t.Fatalf("aggregate events = %d, want exactly one per protocol transition", aggregateCount)
	}
}
