package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func openNotificationTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "notifications.db"), testSecretKey)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func notificationTestEvent(key string, occurred time.Time) models.NotificationEvent {
	return models.NotificationEvent{
		ID:         "event-" + key,
		EventKey:   key,
		IncidentID: "incident-1",
		Category:   models.NotificationCategoryServerHealth,
		Severity:   models.NotificationSeverityWarning,
		Type:       "server.offline",
		EntityType: "server",
		EntityID:   "7",
		Transition: "online->offline",
		Summary:    "Server 7 is offline",
		Detail:     "Sustained reachability checks failed.",
		OccurredAt: occurred,
	}
}

func TestInsertNotificationEventIsIdempotent(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	inserted, status, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:       notificationTestEvent("evt-1", now),
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if !inserted || status != models.NotificationDeliveryPending {
		t.Fatalf("first insert = inserted:%v status:%q, want true/pending", inserted, status)
	}

	inserted, status, err = db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:       notificationTestEvent("evt-1", now.Add(time.Second)),
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatalf("duplicate insert: %v", err)
	}
	if inserted {
		t.Fatal("duplicate event key was inserted again")
	}
	if status != "" {
		t.Fatalf("duplicate status = %q, want empty", status)
	}

	history, err := db.ListNotificationHistory(ctx, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history has %d events, want 1", len(history))
	}
}

func TestInsertNotificationEventCooldownSuppressesRepeatButNotRecovery(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	base := time.Now().UTC()

	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:    notificationTestEvent("evt-1", base),
		Cooldown: time.Minute,
	}); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	repeat := notificationTestEvent("evt-2", base.Add(5*time.Second))
	_, status, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:    repeat,
		Cooldown: time.Minute,
	})
	if err != nil {
		t.Fatalf("repeat insert: %v", err)
	}
	if status != models.NotificationDeliverySuppressed {
		t.Fatalf("repeat status = %q, want suppressed", status)
	}
	delivery, err := db.GetNotificationDeliveryByEventID(ctx, repeat.ID)
	if err != nil {
		t.Fatalf("repeat delivery: %v", err)
	}
	if delivery.LastError != "cooldown" {
		t.Fatalf("cooldown reason = %q, want cooldown", delivery.LastError)
	}

	recovery := notificationTestEvent("evt-3", base.Add(10*time.Second))
	recovery.Recovery = true
	_, status, err = db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:    recovery,
		Cooldown: time.Minute,
	})
	if err != nil {
		t.Fatalf("recovery insert: %v", err)
	}
	if status != models.NotificationDeliveryPending {
		t.Fatalf("recovery status = %q, want pending", status)
	}
}

func TestInsertNotificationEventDropsWhenOutboxIsSaturated(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:    notificationTestEvent("evt-1", now),
		Capacity: 1,
	}); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	second := notificationTestEvent("evt-2", now.Add(time.Second))
	second.IncidentID = "incident-2"
	_, status, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event:    second,
		Capacity: 1,
	})
	if err != nil {
		t.Fatalf("second insert: %v", err)
	}
	if status != models.NotificationDeliveryDropped {
		t.Fatalf("saturated status = %q, want dropped", status)
	}
	delivery, err := db.GetNotificationDeliveryByEventID(ctx, second.ID)
	if err != nil {
		t.Fatalf("saturated delivery: %v", err)
	}
	if delivery.LastError != "queue_full" {
		t.Fatalf("drop reason = %q, want queue_full", delivery.LastError)
	}
}

func TestCommitNotificationTransitionRollsBackStateWhenEventInsertFails(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, changed, err := db.AdvanceNotificationProducerState(ctx, "server_reachability", "7", "online"); err != nil || !changed {
		t.Fatalf("baseline state changed=%v err=%v", changed, err)
	}
	state, generation, found, err := db.ReadNotificationProducerState(ctx, "server_reachability", "7")
	if err != nil || !found || state != "online" {
		t.Fatalf("baseline = state:%q gen:%d found:%v err:%v", state, generation, found, err)
	}

	if _, err := db.sqlDB.ExecContext(ctx, `
		CREATE TRIGGER fail_notification_event
		BEFORE INSERT ON notification_events
		WHEN NEW.summary = 'injected-failure'
		BEGIN SELECT RAISE(ABORT, 'injected event failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	event := notificationTestEvent("evt-atomic", now)
	event.Summary = "injected-failure"
	transition := []NotificationTransition{{
		Producer:           "server_reachability",
		EntityKey:          "7",
		PreviousState:      "online",
		ExpectedGeneration: generation,
		State:              "offline",
	}}
	if _, err := db.CommitNotificationTransition(ctx, transition, NotificationEnqueue{Event: event, MaxAttempts: 3}); err == nil {
		t.Fatal("event insert failure was reported as success")
	}

	state, afterFailureGeneration, found, err := db.ReadNotificationProducerState(ctx, "server_reachability", "7")
	if err != nil || !found {
		t.Fatalf("read after failure found=%v err=%v", found, err)
	}
	if state != "online" || afterFailureGeneration != generation {
		t.Fatalf("state advanced despite failed event insert: state=%q gen=%d, want online/%d", state, afterFailureGeneration, generation)
	}
	if history, _ := db.ListNotificationHistory(ctx, 10); len(history) != 0 {
		t.Fatalf("failed transaction left %d history rows", len(history))
	}

	if _, err := db.sqlDB.ExecContext(ctx, `DROP TRIGGER fail_notification_event`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	inserted, err := db.CommitNotificationTransition(ctx, transition, NotificationEnqueue{Event: event, MaxAttempts: 3})
	if err != nil || !inserted {
		t.Fatalf("retry inserted=%v err=%v", inserted, err)
	}
	history, err := db.ListNotificationHistory(ctx, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 || history[0].Event.ID != event.ID {
		t.Fatalf("history = %#v, want exactly the recovered event", history)
	}

	// Replaying the committed transition is stale, not a second event.
	if _, err := db.CommitNotificationTransition(ctx, transition, NotificationEnqueue{Event: event, MaxAttempts: 3}); !errors.Is(err, ErrNotificationTransitionStale) {
		t.Fatalf("replay error = %v, want ErrNotificationTransitionStale", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 10)
	if len(history) != 1 {
		t.Fatalf("replay produced %d events, want 1", len(history))
	}
}

func TestTerminalUncertainDeliveryDoesNotSaturateOutbox(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	terminal := notificationTestEvent("evt-terminal", now)
	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event: terminal, Status: models.NotificationDeliveryUncertain, MaxAttempts: 2,
	}); err != nil {
		t.Fatalf("insert terminal: %v", err)
	}
	delivery, err := db.GetNotificationDeliveryByEventID(ctx, terminal.ID)
	if err != nil {
		t.Fatalf("get terminal: %v", err)
	}
	if err := db.MarkNotificationRetry(ctx, delivery.ID, 2, 2, now, models.NotificationDeliveryUncertain, "timeout", 0); err != nil {
		t.Fatalf("exhaust terminal: %v", err)
	}

	next := notificationTestEvent("evt-after-terminal", now)
	next.IncidentID = "incident-after"
	_, status, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event: next, Capacity: 1,
	})
	if err != nil {
		t.Fatalf("insert next: %v", err)
	}
	if status != models.NotificationDeliveryPending {
		t.Fatalf("status after terminal = %q, want pending", status)
	}
}

func TestRequeueStaleNotificationDeliveries(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	event := notificationTestEvent("evt-1", time.Now().UTC())
	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{Event: event}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	delivery, err := db.GetNotificationDeliveryByEventID(ctx, event.ID)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	if err := db.MarkNotificationSending(ctx, delivery.ID); err != nil {
		t.Fatalf("mark sending: %v", err)
	}
	if err := db.RequeueStaleNotificationDeliveries(ctx); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	requeued, err := db.GetNotificationDeliveryByEventID(ctx, event.ID)
	if err != nil {
		t.Fatalf("get requeued: %v", err)
	}
	if requeued.Status != models.NotificationDeliveryPending {
		t.Fatalf("requeued status = %q, want pending", requeued.Status)
	}
}

func TestAdvanceNotificationProducerState(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()

	previous, changed, err := db.AdvanceNotificationProducerState(ctx, "producer", "entity", "online")
	if err != nil {
		t.Fatalf("first advance: %v", err)
	}
	if !changed || previous != "" {
		t.Fatalf("first advance = previous:%q changed:%v, want baseline", previous, changed)
	}
	previous, changed, err = db.AdvanceNotificationProducerState(ctx, "producer", "entity", "online")
	if err != nil {
		t.Fatalf("repeat advance: %v", err)
	}
	if changed || previous != "online" {
		t.Fatalf("repeat advance = previous:%q changed:%v, want unchanged", previous, changed)
	}
	previous, changed, err = db.AdvanceNotificationProducerState(ctx, "producer", "entity", "offline")
	if err != nil {
		t.Fatalf("changed advance: %v", err)
	}
	if !changed || previous != "online" {
		t.Fatalf("changed advance = previous:%q changed:%v", previous, changed)
	}
}

func TestDueNotificationDispatchHonoursForceAndRetryState(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	force := notificationTestEvent("evt-force", now)
	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event: force, Status: models.NotificationDeliveryPending, Force: true, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("insert force: %v", err)
	}
	normal := notificationTestEvent("evt-normal", now)
	normal.ID = "event-normal"
	normal.IncidentID = "incident-2"
	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event: normal, Status: models.NotificationDeliveryPending, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("insert normal: %v", err)
	}

	dueAt := now.Add(time.Minute)
	onlyForced, err := db.DueNotificationDispatch(ctx, dueAt, 10, false)
	if err != nil {
		t.Fatalf("forced dispatch: %v", err)
	}
	if len(onlyForced) != 1 || !onlyForced[0].Force {
		t.Fatalf("forced dispatch = %#v, want only the explicit test", onlyForced)
	}
	all, err := db.DueNotificationDispatch(ctx, dueAt, 10, true)
	if err != nil {
		t.Fatalf("all dispatch: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("all dispatch returned %d, want 2", len(all))
	}

	// A retryable uncertain delivery is due; an exhausted one is not.
	if _, _, err := db.InsertNotificationEvent(ctx, NotificationEnqueue{
		Event: func() models.NotificationEvent {
			e := notificationTestEvent("evt-retry", now)
			e.ID = "event-retry"
			e.IncidentID = "incident-3"
			return e
		}(),
		Status: models.NotificationDeliveryUncertain, MaxAttempts: 2,
	}); err != nil {
		t.Fatalf("insert retryable: %v", err)
	}
	retryDelivery, err := db.GetNotificationDeliveryByEventID(ctx, "event-retry")
	if err != nil {
		t.Fatalf("get retryable: %v", err)
	}
	if err := db.MarkNotificationRetry(ctx, retryDelivery.ID, 1, 2, now, models.NotificationDeliveryUncertain, "timeout", 0); err != nil {
		t.Fatalf("mark retryable: %v", err)
	}
	all, err = db.DueNotificationDispatch(ctx, dueAt, 10, true)
	if err != nil {
		t.Fatalf("retryable dispatch: %v", err)
	}
	if !containsDispatch(all, "event-retry") {
		t.Fatal("retryable uncertain delivery is not due")
	}
	if err := db.MarkNotificationRetry(ctx, retryDelivery.ID, 2, 2, now, models.NotificationDeliveryUncertain, "timeout", 0); err != nil {
		t.Fatalf("exhaust retryable: %v", err)
	}
	all, err = db.DueNotificationDispatch(ctx, dueAt, 10, true)
	if err != nil {
		t.Fatalf("exhausted dispatch: %v", err)
	}
	if containsDispatch(all, "event-retry") {
		t.Fatal("exhausted uncertain delivery was returned as due")
	}
}

func containsDispatch(items []models.NotificationDispatch, eventID string) bool {
	for _, item := range items {
		if item.Event.ID == eventID {
			return true
		}
	}
	return false
}

func TestGetActiveProtocols(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	userID, err := db.CreateUser(ctx, &models.User{Username: "protocol-user", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: 0, Protocol: models.ProtocolAWG, ClientID: "c1",
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: 0, Protocol: models.ProtocolVLESS, ClientID: "c2",
	}); err != nil {
		t.Fatalf("create second connection: %v", err)
	}
	protocols, err := db.GetActiveProtocols(ctx)
	if err != nil {
		t.Fatalf("active protocols: %v", err)
	}
	if len(protocols) != 2 {
		t.Fatalf("protocols = %v, want two distinct", protocols)
	}
}

func TestNotificationProducerStateGenerationMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-producer.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE notification_producer_state (
			producer TEXT NOT NULL,
			entity_key TEXT NOT NULL,
			state TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (producer, entity_key)
		);
		INSERT INTO notification_producer_state (producer, entity_key, state, updated_at)
		VALUES ('server_reachability', '7', 'online', '2026-11-18T00:00:00Z');`); err != nil {
		t.Fatalf("seed legacy table: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	state, generation, found, err := db.ReadNotificationProducerState(context.Background(), "server_reachability", "7")
	if err != nil || !found || state != "online" || generation != 0 {
		t.Fatalf("migrated row = state:%q gen:%d found:%v err:%v", state, generation, found, err)
	}
	if _, _, err := db.AdvanceNotificationProducerState(context.Background(), "server_reachability", "7", "offline"); err != nil {
		t.Fatalf("advance migrated row: %v", err)
	}
	_, generation, _, _ = db.ReadNotificationProducerState(context.Background(), "server_reachability", "7")
	if generation != 1 {
		t.Fatalf("generation after advance = %d, want 1", generation)
	}
}

func TestAdvanceNotificationTransitionsIsAtomic(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()

	if _, _, err := db.AdvanceNotificationProducerState(ctx, "p1", "e1", "a"); err != nil {
		t.Fatalf("seed p1: %v", err)
	}
	_, generation, _, err := db.ReadNotificationProducerState(ctx, "p1", "e1")
	if err != nil {
		t.Fatalf("read p1: %v", err)
	}
	if err := db.AdvanceNotificationTransitions(ctx, []NotificationTransition{
		{Producer: "p1", EntityKey: "e1", PreviousState: "a", ExpectedGeneration: generation, State: "b"},
		{Producer: "p2", EntityKey: "e2", State: "x"},
	}); err != nil {
		t.Fatalf("advance both: %v", err)
	}
	for _, tc := range []struct{ producer, entity, state string }{
		{"p1", "e1", "b"}, {"p2", "e2", "x"},
	} {
		state, _, found, err := db.ReadNotificationProducerState(ctx, tc.producer, tc.entity)
		if err != nil || !found || state != tc.state {
			t.Fatalf("%s/%s = %q found=%v err=%v, want %q", tc.producer, tc.entity, state, found, err, tc.state)
		}
	}

	// A stale member rolls back the whole batch.
	err = db.AdvanceNotificationTransitions(ctx, []NotificationTransition{
		{Producer: "p2", EntityKey: "e2", PreviousState: "x", ExpectedGeneration: 4, State: "y"},
		{Producer: "p1", EntityKey: "e1", PreviousState: "b", ExpectedGeneration: generation + 1, State: "c"},
	})
	if !errors.Is(err, ErrNotificationTransitionStale) {
		t.Fatalf("stale batch error = %v", err)
	}
	state, _, _, _ := db.ReadNotificationProducerState(ctx, "p1", "e1")
	if state != "b" {
		t.Fatalf("stale batch partially advanced p1 to %q", state)
	}
}

func TestNotificationSettingsTokenIsEncryptedAtRest(t *testing.T) {
	db := openNotificationTestDB(t)
	ctx := context.Background()
	settings := models.DefaultNotificationSettings()
	settings.URL = "https://gotify.example.test"
	settings.AppToken = "super-secret-app-token"
	if err := db.SetSetting(ctx, "notifications", settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	raw, found, err := db.GetSettingRaw(ctx, "notifications")
	if err != nil || !found {
		t.Fatalf("raw setting found=%v err=%v", found, err)
	}
	if strings.Contains(raw.String, "super-secret-app-token") {
		t.Fatal("application token is stored in plaintext")
	}

	var loaded models.NotificationSettings
	if err := db.GetSetting(ctx, "notifications", &loaded); err != nil {
		t.Fatalf("load settings: %v", err)
	}
	if loaded.AppToken != "super-secret-app-token" {
		t.Fatalf("decrypted token = %q, want stored token", loaded.AppToken)
	}
}
