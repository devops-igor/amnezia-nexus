package notifications

import (
	"context"
	"testing"

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
