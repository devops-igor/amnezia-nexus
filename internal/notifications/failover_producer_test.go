package notifications

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestFailoverProducerRecordsTruthfulOutcomes(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	producer := NewFailoverProducer(db, notifier)
	ctx := context.Background()

	if err := producer.publish(ctx, models.FailoverOutcome{
		SourceTunnelID: 7, SourceServerID: 3, Protocol: models.ProtocolAWG,
		Decision: "no_target",
	}); err != nil {
		t.Fatalf("publish no target: %v", err)
	}
	noTarget := observerTestEvent(t, notifier, "failover.no_target")
	if noTarget.Event.Severity != models.NotificationSeverityCritical {
		t.Fatalf("no-target severity = %q", noTarget.Event.Severity)
	}
	if noTarget.Event.IncidentID != "backend:7" {
		t.Fatalf("incident id = %q, want backend:7", noTarget.Event.IncidentID)
	}

	if err := producer.publish(ctx, models.FailoverOutcome{
		SourceTunnelID: 7, Decision: "partial", Migrated: 2, Stranded: 1,
	}); err != nil {
		t.Fatalf("publish partial: %v", err)
	}
	partial := observerTestEvent(t, notifier, "failover.partial")
	if partial.Event.Severity != models.NotificationSeverityCritical {
		t.Fatalf("partial severity = %q", partial.Event.Severity)
	}

	// Repeating the identical outcome is not a second transition.
	if err := producer.publish(ctx, models.FailoverOutcome{
		SourceTunnelID: 7, Decision: "partial", Migrated: 2, Stranded: 1,
	}); err != nil {
		t.Fatalf("repeat publish: %v", err)
	}
	history, _ := db.ListNotificationHistory(ctx, 20)
	var partialCount int
	for _, item := range history {
		if item.Event.Type == "failover.partial" {
			partialCount++
		}
	}
	if partialCount != 1 {
		t.Fatalf("partial events = %d, want 1", partialCount)
	}

	if err := producer.publish(ctx, models.FailoverOutcome{
		SourceTunnelID: 7, Decision: "success", Migrated: 2,
	}); err != nil {
		t.Fatalf("publish success: %v", err)
	}
	if observerTestEvent(t, notifier, "failover.succeeded").Event.Silent {
		t.Fatal("automatic failover success must be a real informational delivery")
	}

	// The same counts on a later tunnel transition (new state version) are a
	// distinct incident and must not be suppressed by the earlier one.
	if err := producer.publish(ctx, models.FailoverOutcome{
		SourceTunnelID: 7, Decision: "success", Migrated: 2, StateVersion: 4,
	}); err != nil {
		t.Fatalf("publish later success: %v", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 20)
	var successCount int
	for _, item := range history {
		if item.Event.Type == "failover.succeeded" {
			successCount++
		}
	}
	if successCount != 2 {
		t.Fatalf("success events = %d, want 2 distinct transitions", successCount)
	}
}

func TestFailoverProducerManualSuccessIsHistoryOnly(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	producer := NewFailoverProducer(db, notifier)
	if err := producer.publish(context.Background(), models.FailoverOutcome{
		SourceTunnelID: 9, Decision: "success", Migrated: 1, Manual: true,
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	item := observerTestEvent(t, notifier, "failover.succeeded")
	if item.Delivery.Status != models.NotificationDeliverySuppressed || item.Delivery.LastError != "history_only" {
		t.Fatalf("manual success delivery = %#v, want history_only", item.Delivery)
	}
}

type triggerDroppingPublisher struct {
	inner   *Service
	raw     *sql.DB
	dropped bool
}

func (p *triggerDroppingPublisher) PublishTransition(ctx context.Context, transitions []database.NotificationTransition, event models.NotificationEvent) (PublishResult, error) {
	result, err := p.inner.PublishTransition(ctx, transitions, event)
	if err != nil && !p.dropped {
		if _, dropErr := p.raw.Exec(`DROP TRIGGER fail_failover_event`); dropErr != nil {
			return result, dropErr
		}
		p.dropped = true
	}
	return result, err
}

func TestFailoverProducerRetriesTransientDatabaseFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failover-retry.db")
	db, err := database.Open(path, notificationTestSecret)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TRIGGER fail_failover_event
		BEFORE INSERT ON notification_events
		WHEN NEW.event_type = 'failover.no_target'
		BEGIN
			SELECT RAISE(ABORT, 'injected failover event failure');
		END;`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}

	notifier := NewService(db, Options{})
	publisher := &triggerDroppingPublisher{inner: notifier, raw: raw}
	producer := NewFailoverProducer(db, publisher,
		WithFailoverRetry(5, func(int) time.Duration { return 10 * time.Millisecond }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- producer.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("producer did not stop")
		}
	})

	producer.NotifyFailoverOutcome(models.FailoverOutcome{
		SourceTunnelID: 42,
		SourceServerID: 3,
		Protocol:       models.ProtocolAWG,
		Decision:       "no_target",
	})

	deadline := time.Now().Add(3 * time.Second)
	var history []models.NotificationHistoryItem
	for time.Now().Before(deadline) {
		history, err = db.ListNotificationHistory(ctx, 20)
		if err != nil {
			t.Fatalf("history: %v", err)
		}
		if len(history) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(history) != 1 || history[0].Event.Type != "failover.no_target" {
		t.Fatalf("history = %#v, want one recovered failover event", history)
	}
	if !publisher.dropped {
		t.Fatal("test did not exercise the injected SQLite insert failure")
	}
}

func TestDefaultFailoverRetryBackoffIsBounded(t *testing.T) {
	if got := defaultFailoverRetryBackoff(1); got != time.Second {
		t.Fatalf("backoff(1) = %v", got)
	}
	if got := defaultFailoverRetryBackoff(3); got != 4*time.Second {
		t.Fatalf("backoff(3) = %v", got)
	}
	if got := defaultFailoverRetryBackoff(30); got != 30*time.Second {
		t.Fatalf("backoff(30) = %v, want capped", got)
	}
	if got := defaultFailoverRetryBackoff(0); got != time.Second {
		t.Fatalf("backoff(0) = %v", got)
	}
}

func TestFailoverProducerDrainsQueuedOutcomeOnShutdown(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	producer := NewFailoverProducer(db, notifier)
	producer.outcomes <- models.FailoverOutcome{
		SourceTunnelID: 77, Decision: "partial", Migrated: 1, Stranded: 1, StateVersion: 1,
	}
	producer.drainOnShutdown([]failoverWork{{
		outcome: models.FailoverOutcome{
			SourceTunnelID: 76, Decision: "no_target", StateVersion: 1,
		},
	}})

	history, err := db.ListNotificationHistory(context.Background(), 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	types := map[string]int{}
	for _, item := range history {
		types[item.Event.Type]++
	}
	if types["failover.no_target"] != 1 || types["failover.partial"] != 1 {
		t.Fatalf("drained events = %#v, want both queued outcomes", types)
	}
}
