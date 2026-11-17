package notifications

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/upstream"
)

type fakeUpdateChecker struct {
	status *upstream.UpstreamStatus
	err    error
}

func (f *fakeUpdateChecker) Check(context.Context, bool) (*upstream.UpstreamStatus, error) {
	return f.status, f.err
}

func component(name, pinned, latest string, update bool) upstream.ComponentStatus {
	return upstream.ComponentStatus{
		Name: name, PinnedVersion: pinned, LatestVersion: latest,
		UpdateAvailable: update,
		ReleaseURL:      "https://github.com/example/" + name + "/releases/tag/" + latest,
	}
}

func TestUpdateObserverNotifiesOncePerDiscoveredVersion(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	checker := &fakeUpdateChecker{status: &upstream.UpstreamStatus{Components: []upstream.ComponentStatus{
		component("amneziawg-go", "v1", "v1", false),
	}}}
	observer := NewUpdateObserver(db, notifier, checker, UpdateObserverOptions{Now: time.Now})
	ctx := context.Background()

	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if history, _ := db.ListNotificationHistory(ctx, 20); len(history) != 0 {
		t.Fatalf("up-to-date inventory produced %d events", len(history))
	}

	checker.status = &upstream.UpstreamStatus{Components: []upstream.ComponentStatus{
		component("amneziawg-go", "v1", "v2", true),
	}}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("update observe: %v", err)
	}
	event := observerTestEvent(t, notifier, "software.update_available")
	if event.Event.Severity != models.NotificationSeverityInfo {
		t.Fatalf("severity = %q", event.Event.Severity)
	}
	if event.Event.Detail == "" || event.Event.Detail == "v1 -> v2" {
		t.Fatalf("detail = %q", event.Event.Detail)
	}

	// A repeated check of the same component+version is suppressed.
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("repeat observe: %v", err)
	}
	history, _ := db.ListNotificationHistory(ctx, 20)
	if len(history) != 1 {
		t.Fatalf("repeat check produced %d events, want 1", len(history))
	}

	// A newer release after an announced one is not suppressed.
	checker.status = &upstream.UpstreamStatus{Components: []upstream.ComponentStatus{
		component("amneziawg-go", "v1", "v3", true),
	}}
	if err := observer.ObserveOnce(ctx); err != nil {
		t.Fatalf("newer observe: %v", err)
	}
	history, _ = db.ListNotificationHistory(ctx, 20)
	if len(history) != 2 {
		t.Fatalf("newer release produced %d events, want 2", len(history))
	}
}

func TestUpdateObserverGroupsReleasesAndSkipsPartialFailures(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	checker := &fakeUpdateChecker{status: &upstream.UpstreamStatus{Components: []upstream.ComponentStatus{
		component("amneziawg-go", "v1", "v2", true),
		component("amneziawg-tools", "v1", "v2", true),
		{Name: "docker-base-image", PinnedVersion: "v1", Error: "rate limited"},
	}}}
	observer := NewUpdateObserver(db, notifier, checker, UpdateObserverOptions{Now: time.Now})
	if err := observer.ObserveOnce(context.Background()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	history, _ := db.ListNotificationHistory(context.Background(), 20)
	if len(history) != 1 {
		t.Fatalf("grouped check produced %d events, want 1", len(history))
	}
	detail := history[0].Event.Detail
	if !strings.Contains(detail, "amneziawg-go") || !strings.Contains(detail, "amneziawg-tools") {
		t.Fatalf("grouped detail = %q", detail)
	}
	if strings.Contains(detail, "docker-base-image") {
		t.Fatalf("partial failure was reported as a release: %q", detail)
	}
}

func TestUpdateObserverLifecycleStartsAndStops(t *testing.T) {
	db := openNotificationDB(t)
	observer := NewUpdateObserver(db, NewService(db, Options{}), &fakeUpdateChecker{
		status: &upstream.UpstreamStatus{},
	}, UpdateObserverOptions{Interval: 10 * time.Millisecond})
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
		t.Fatal("update observer did not exit")
	}
}

func TestUpdateObserverCheckerFailureDoesNotFabricateRelease(t *testing.T) {
	db := openNotificationDB(t)
	notifier := NewService(db, Options{})
	checker := &fakeUpdateChecker{err: errors.New("github unavailable")}
	observer := NewUpdateObserver(db, notifier, checker, UpdateObserverOptions{Now: time.Now})
	if err := observer.ObserveOnce(context.Background()); err == nil {
		t.Fatal("checker failure was reported as success")
	}
	if history, _ := db.ListNotificationHistory(context.Background(), 20); len(history) != 0 {
		t.Fatalf("checker failure produced %d events", len(history))
	}
}
