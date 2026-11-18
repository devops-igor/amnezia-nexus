package notifications

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const notificationTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func openNotificationDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "notifications.db"), notificationTestSecret)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func saveNotificationSettings(t *testing.T, db *database.DB, settings models.NotificationSettings) {
	t.Helper()
	if err := db.SetSetting(context.Background(), "notifications", settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
}

func startNotificationService(t *testing.T, svc *Service) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = svc.Start(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("notification service did not stop")
		}
	})
}

type capturedRequest struct {
	Path   string
	Token  string
	Body   map[string]any
	Method string
}

func notificationReceiver(t *testing.T) (*httptest.Server, chan capturedRequest) {
	t.Helper()
	requests := make(chan capturedRequest, 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requests <- capturedRequest{
			Path:   r.URL.Path,
			Token:  r.Header.Get("X-Gotify-Key"),
			Body:   body,
			Method: r.Method,
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func enabledSettings(url, token string) models.NotificationSettings {
	settings := models.DefaultNotificationSettings()
	settings.Enabled = true
	settings.URL = url
	settings.AppToken = token
	settings.MaxAttempts = 3
	return settings
}

func testEvent(key string) models.NotificationEvent {
	return models.NotificationEvent{
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
		Evidence:   "three consecutive probes failed",
	}
}

func TestDisabledModeRecordsEventButSendsNothing(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	settings := enabledSettings(server.URL, "token")
	settings.Enabled = false
	saveNotificationSettings(t, db, settings)

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, svc)

	result, err := svc.Publish(context.Background(), testEvent("evt-disabled"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if result.Status != models.NotificationDeliverySuppressed {
		t.Fatalf("status = %q, want suppressed", result.Status)
	}

	history, err := db.ListNotificationHistory(context.Background(), 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 || history[0].Delivery.LastError != "disabled" {
		t.Fatalf("history = %#v, want one disabled event", history)
	}

	select {
	case req := <-requests:
		t.Fatalf("disabled mode sent an outbound request: %#v", req)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestEventFlowsThroughDurableStoreToReceiver(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token-123"))

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, svc)

	result, err := svc.Publish(context.Background(), testEvent("evt-delivery"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !result.Inserted || result.Status != models.NotificationDeliveryPending {
		t.Fatalf("publish result = %#v, want inserted pending", result)
	}

	select {
	case req := <-requests:
		if req.Path != "/message" {
			t.Fatalf("path = %q, want /message", req.Path)
		}
		if req.Token != "token-123" {
			t.Fatalf("token header = %q, want the application token", req.Token)
		}
		if req.Body["title"] != "Server 7 is offline" {
			t.Fatalf("title = %v", req.Body["title"])
		}
		if !strings.Contains(req.Body["message"].(string), "three consecutive probes failed") {
			t.Fatalf("message missing evidence: %v", req.Body["message"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notification reached the receiver")
	}

	delivery, err := svc.WaitForDelivery(context.Background(), result.EventID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("wait delivery: %v", err)
	}
	if delivery.Status != models.NotificationDeliverySent || delivery.Attempts != 1 {
		t.Fatalf("delivery = %#v, want sent on first attempt", delivery)
	}
}

func TestDuplicateEventKeySendsOneNotification(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token"))
	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, svc)

	first, err := svc.Publish(context.Background(), testEvent("evt-dup"))
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	second, err := svc.Publish(context.Background(), testEvent("evt-dup"))
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if !first.Inserted || second.Inserted {
		t.Fatalf("insert flags = %v/%v, want true/false", first.Inserted, second.Inserted)
	}

	select {
	case <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("no notification reached the receiver")
	}
	select {
	case extra := <-requests:
		t.Fatalf("duplicate event sent twice: %#v", extra)
	case <-time.After(150 * time.Millisecond):
	}
	history, _ := db.ListNotificationHistory(context.Background(), 10)
	if len(history) != 1 {
		t.Fatalf("history has %d events, want 1", len(history))
	}
}

func TestRateLimitedDeliveryRetriesAndSucceeds(t *testing.T) {
	db := openNotificationDB(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`retry later`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token"))

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, svc)
	result, err := svc.Publish(context.Background(), testEvent("evt-429"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	delivery, err := svc.WaitForDelivery(context.Background(), result.EventID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if delivery.Status != models.NotificationDeliverySent || delivery.Attempts != 2 {
		t.Fatalf("delivery = %#v, want sent on attempt 2", delivery)
	}
	if calls.Load() != 2 {
		t.Fatalf("receiver calls = %d, want 2", calls.Load())
	}
}

func TestTransportTimeoutIsReportedAsUncertainAfterBoundedRetries(t *testing.T) {
	db := openNotificationDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	settings := enabledSettings(server.URL, "token")
	settings.MaxAttempts = 2
	saveNotificationSettings(t, db, settings)

	slowClient := &http.Client{Timeout: 40 * time.Millisecond}
	svc := NewService(db, Options{
		Client:       NewClient(WithHTTPClient(slowClient)),
		PollInterval: 10 * time.Millisecond,
		Backoff:      func(int) time.Duration { return time.Millisecond },
	})
	startNotificationService(t, svc)

	result, err := svc.Publish(context.Background(), testEvent("evt-timeout"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	delivery, err := svc.WaitForDelivery(waitCtx, result.EventID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if delivery.Status != models.NotificationDeliveryUncertain {
		t.Fatalf("status = %q, want uncertain", delivery.Status)
	}
	if delivery.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", delivery.Attempts)
	}
}

func TestExplicitTestNotificationSendsWhileDeliveryIsDisabled(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	settings := enabledSettings(server.URL, "token")
	settings.Enabled = false
	saveNotificationSettings(t, db, settings)

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	startNotificationService(t, svc)

	eventID, err := svc.SendTest(context.Background(), "Test", "Administrator test")
	if err != nil {
		t.Fatalf("send test: %v", err)
	}
	select {
	case req := <-requests:
		if req.Body["title"] != "Test" {
			t.Fatalf("title = %v", req.Body["title"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("explicit test did not reach the receiver")
	}
	delivery, err := svc.WaitForDelivery(context.Background(), eventID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if delivery.Status != models.NotificationDeliverySent {
		t.Fatalf("test delivery = %#v, want sent", delivery)
	}
}

func TestCategoryAndSeverityFiltersSuppress(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	settings := enabledSettings(server.URL, "token")
	settings.Categories[string(models.NotificationCategoryServerHealth)] = false
	settings.MinSeverity = models.NotificationSeverityCritical
	saveNotificationSettings(t, db, settings)

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond})
	startNotificationService(t, svc)

	categoryOff, err := svc.Publish(context.Background(), testEvent("evt-category-off"))
	if err != nil {
		t.Fatalf("publish category off: %v", err)
	}
	if categoryOff.Status != models.NotificationDeliverySuppressed {
		t.Fatalf("category-off status = %q", categoryOff.Status)
	}

	below := testEvent("evt-below-severity")
	below.Category = models.NotificationCategoryUpdates
	below.Severity = models.NotificationSeverityWarning
	below.IncidentID = "incident-2"
	belowResult, err := svc.Publish(context.Background(), below)
	if err != nil {
		t.Fatalf("publish below severity: %v", err)
	}
	if belowResult.Status != models.NotificationDeliverySuppressed {
		t.Fatalf("below-severity status = %q", belowResult.Status)
	}

	select {
	case req := <-requests:
		t.Fatalf("suppressed event was sent: %#v", req)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRestartResumesAnInFlightDelivery(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token"))

	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond, Backoff: func(int) time.Duration { return time.Millisecond }})
	result, err := svc.Publish(context.Background(), testEvent("evt-restart"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	delivery, err := db.GetNotificationDeliveryByEventID(context.Background(), result.EventID)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	// Simulate a crash while the HTTP attempt was in flight.
	if err := db.MarkNotificationSending(context.Background(), delivery.ID); err != nil {
		t.Fatalf("mark sending: %v", err)
	}

	startNotificationService(t, svc)
	select {
	case <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("restarted dispatcher did not resume the in-flight delivery")
	}
	final, err := svc.WaitForDelivery(context.Background(), result.EventID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if final.Status != models.NotificationDeliverySent {
		t.Fatalf("final status = %q, want sent", final.Status)
	}
}

func TestSaturatedOutboxRecoversAfterDraining(t *testing.T) {
	db := openNotificationDB(t)
	server, requests := notificationReceiver(t)
	saveNotificationSettings(t, db, enabledSettings(server.URL, "token"))
	svc := NewService(db, Options{
		PollInterval:   10 * time.Millisecond,
		OutboxCapacity: 1,
		Backoff:        func(int) time.Duration { return time.Millisecond },
	})

	first, err := svc.Publish(context.Background(), testEvent("evt-first"))
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	secondEvent := testEvent("evt-second")
	secondEvent.IncidentID = "incident-2"
	second, err := svc.Publish(context.Background(), secondEvent)
	if err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if second.Status != models.NotificationDeliveryDropped {
		t.Fatalf("saturated delivery status = %q, want dropped", second.Status)
	}

	startNotificationService(t, svc)
	select {
	case <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("queued delivery did not drain")
	}
	if _, err := svc.WaitForDelivery(context.Background(), first.EventID, 10*time.Millisecond); err != nil {
		t.Fatalf("wait first: %v", err)
	}

	thirdEvent := testEvent("evt-third")
	thirdEvent.IncidentID = "incident-3"
	third, err := svc.Publish(context.Background(), thirdEvent)
	if err != nil {
		t.Fatalf("third publish: %v", err)
	}
	if third.Status != models.NotificationDeliveryPending {
		t.Fatalf("post-drain status = %q, want pending", third.Status)
	}
}

func TestDefaultBackoffIsBounded(t *testing.T) {
	if got := defaultBackoff(1); got != time.Second {
		t.Fatalf("backoff(1) = %v", got)
	}
	if got := defaultBackoff(3); got != 4*time.Second {
		t.Fatalf("backoff(3) = %v", got)
	}
	if got := defaultBackoff(30); got != 5*time.Minute {
		t.Fatalf("backoff(30) = %v, want capped", got)
	}
	if got := defaultBackoff(0); got != time.Second {
		t.Fatalf("backoff(0) = %v", got)
	}
}

func TestServiceLifecycleStartsAndStops(t *testing.T) {
	db := openNotificationDB(t)
	svc := NewService(db, Options{PollInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Start(ctx) }()
	time.Sleep(20 * time.Millisecond)
	if err := svc.Start(context.Background()); err == nil {
		t.Fatal("second Start was accepted")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := svc.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not exit")
	}
}

func TestObserverLifecycleStartsAndStops(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	observer := NewObserver(db, notifier, ObserverOptions{Interval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- observer.Start(ctx) }()
	time.Sleep(20 * time.Millisecond)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := observer.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not exit")
	}
}

func TestFailoverProducerLifecycleAndSaturation(t *testing.T) {
	db := openNotificationDB(t)
	producer := NewFailoverProducer(db, NewService(db, Options{}))
	for i := 0; i < failoverOutcomeBuffer; i++ {
		producer.NotifyFailoverOutcome(models.FailoverOutcome{SourceTunnelID: int64(i + 1), Decision: "success"})
	}
	// A saturated buffer must drop rather than block the caller.
	producer.NotifyFailoverOutcome(models.FailoverOutcome{SourceTunnelID: 999, Decision: "partial"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- producer.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := producer.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not exit")
	}
}

func TestPublishRejectsIncompleteEvent(t *testing.T) {
	db := openNotificationDB(t)
	svc := NewService(db, Options{})
	if _, err := svc.Publish(context.Background(), models.NotificationEvent{}); err == nil {
		t.Fatal("empty event was accepted")
	}
	event := testEvent("")
	if _, err := svc.Publish(context.Background(), event); err == nil {
		t.Fatal("event without key was accepted")
	}
}
