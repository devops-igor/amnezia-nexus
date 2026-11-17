package notifications

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/upstream"
)

const defaultUpdateObserverInterval = 30 * time.Minute

// UpdateChecker is the authoritative upstream release comparison service. It
// already owns caching, ETag handling and version comparison; this observer only
// consumes its result.
type UpdateChecker interface {
	Check(ctx context.Context, forceRefresh bool) (*upstream.UpstreamStatus, error)
}

// UpdateObserverOptions configure the update notification producer.
type UpdateObserverOptions struct {
	Interval time.Duration
	Now      func() time.Time
}

// UpdateObserver notifies once per newly discovered monitored release. It never
// upgrades anything and never treats a failed or partial read as a release.
type UpdateObserver struct {
	checker  UpdateChecker
	notifier *Service
	db       notificationStateStore
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

// NewUpdateObserver builds the Phase 4 producer. db is satisfied by *database.DB.
func NewUpdateObserver(db notificationStateStore, notifier *Service, checker UpdateChecker, opts UpdateObserverOptions) *UpdateObserver {
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultUpdateObserverInterval
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &UpdateObserver{
		checker:  checker,
		notifier: notifier,
		db:       db,
		interval: interval,
		now:      now,
		logger:   slog.Default().With("component", "notification-update-observer"),
	}
}

type notificationStateStore interface {
	ReadNotificationProducerState(ctx context.Context, producer, entityKey string) (string, int64, bool, error)
	CommitNotificationTransition(ctx context.Context, transitions []database.NotificationTransition, req database.NotificationEnqueue) (bool, error)
}

// Name implements service.BackgroundService.
func (o *UpdateObserver) Name() string { return "notification-update-observer" }

// Start implements service.BackgroundService.
func (o *UpdateObserver) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return errors.New("notification update observer is already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	o.cancel = cancel
	o.done = make(chan struct{})
	o.running = true
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.running = false
		close(o.done)
		o.mu.Unlock()
	}()

	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		if runCtx.Err() != nil {
			return nil
		}
		if err := o.ObserveOnce(runCtx); err != nil && runCtx.Err() == nil {
			o.logger.Warn("Update notification pass failed", "err", err)
		}
		select {
		case <-runCtx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Stop implements service.BackgroundService.
func (o *UpdateObserver) Stop(ctx context.Context) error {
	o.mu.Lock()
	cancel := o.cancel
	done := o.done
	running := o.running
	o.mu.Unlock()
	if !running || cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ObserveOnce checks the authoritative inventory and publishes at most one
// grouped event for newly discovered releases.
func (o *UpdateObserver) ObserveOnce(ctx context.Context) error {
	if o.checker == nil || o.notifier == nil || o.db == nil {
		return errors.New("update notification observer is not configured")
	}
	status, err := o.checker.Check(ctx, false)
	if err != nil {
		return fmt.Errorf("check upstream releases: %w", err)
	}
	if status == nil {
		return nil
	}

	changed, err := o.collectUpdatedComponents(ctx, status)
	if err != nil {
		return err
	}
	if len(changed) == 0 {
		return nil
	}
	return o.publishChanges(ctx, changed)
}

func (o *UpdateObserver) publishChanges(ctx context.Context, changed []updateChange) error {
	sort.Slice(changed, func(i, j int) bool { return changed[i].component.Name < changed[j].component.Name })
	now := o.now()
	components := make([]upstream.ComponentStatus, len(changed))
	transitions := make([]database.NotificationTransition, len(changed))
	for i, change := range changed {
		components[i] = change.component
		transitions[i] = database.NotificationTransition{
			Producer:           "software_update",
			EntityKey:          change.component.Name,
			PreviousState:      change.previous,
			ExpectedGeneration: change.generation,
			State:              change.component.LatestVersion,
		}
	}
	event := modelsNotificationEventForUpdates(components, now)
	event.EventKey = TransitionEventKey("software_update", changed[0].component.Name, changed[0].generation+1, changed[0].component.LatestVersion)
	if _, err := o.notifier.PublishTransition(ctx, transitions, event); err != nil {
		if errors.Is(err, database.ErrNotificationTransitionStale) {
			// Another pass advanced one component; the next scheduled check
			// observes the same remaining releases and retries atomically.
			return nil
		}
		return err
	}
	return nil
}

type updateChange struct {
	component  upstream.ComponentStatus
	previous   string
	generation int64
}

func (o *UpdateObserver) collectUpdatedComponents(ctx context.Context, status *upstream.UpstreamStatus) ([]updateChange, error) {
	var changed []updateChange
	for _, component := range status.Components {
		change, ok, err := o.updateChange(ctx, component)
		if err != nil {
			return nil, err
		}
		if ok {
			changed = append(changed, change)
		}
	}
	return changed, nil
}

func (o *UpdateObserver) updateChange(ctx context.Context, component upstream.ComponentStatus) (updateChange, bool, error) {
	if component.Error != "" || !component.UpdateAvailable {
		return updateChange{}, false, nil
	}
	if strings.TrimSpace(component.LatestVersion) == "" || strings.TrimSpace(component.PinnedVersion) == "" {
		return updateChange{}, false, nil
	}
	state, generation, found, err := o.db.ReadNotificationProducerState(ctx, "software_update", component.Name)
	if err != nil {
		return updateChange{}, false, err
	}
	if found && state == component.LatestVersion {
		return updateChange{}, false, nil
	}
	previous := ""
	if found {
		previous = state
	}
	return updateChange{component: component, previous: previous, generation: generation}, true, nil
}

func modelsNotificationEventForUpdates(changed []upstream.ComponentStatus, now time.Time) (event models.NotificationEvent) {
	names := make([]string, len(changed))
	var details strings.Builder
	for i, component := range changed {
		names[i] = component.Name
		if details.Len() > 0 {
			details.WriteString("\n")
		}
		details.WriteString(fmt.Sprintf("%s: %s -> %s", component.Name, component.PinnedVersion, component.LatestVersion))
		if component.ReleaseURL != "" {
			details.WriteString(" (")
			details.WriteString(component.ReleaseURL)
			details.WriteString(")")
		}
	}
	var summary string
	if len(changed) > 1 {
		summary = fmt.Sprintf("%d monitored software updates available", len(changed))
	} else {
		summary = fmt.Sprintf("Update available for %s", changed[0].Name)
	}
	return models.NotificationEvent{
		EventKey:   "software_update:" + strings.Join(names, ",") + ":" + strings.Join(componentVersions(changed), ","),
		IncidentID: "software_updates:" + strings.Join(names, ","),
		Category:   models.NotificationCategoryUpdates,
		Severity:   models.NotificationSeverityInfo,
		Type:       "software.update_available",
		EntityType: "software",
		EntityID:   changed[0].Name,
		Transition: "update_available",
		Summary:    summary,
		Detail:     details.String(),
		Evidence:   "fresh upstream version comparison; no upgrade was performed",
		OccurredAt: now,
	}
}

func componentVersions(changed []upstream.ComponentStatus) []string {
	versions := make([]string, len(changed))
	for i, component := range changed {
		versions[i] = component.Name + "=" + component.LatestVersion
	}
	return versions
}
