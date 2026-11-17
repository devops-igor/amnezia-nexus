package notifications

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	defaultPollInterval = 2 * time.Second
	defaultOutboxCap    = 500
)

// Options configure the notification service. Tests use them to keep backoff
// and polling deterministic; production uses the defaults.
type Options struct {
	Client         *Client
	PollInterval   time.Duration
	OutboxCapacity int
	Now            func() time.Time
	Backoff        func(attempt int) time.Duration
}

// Service owns notification policy, durable ingestion and the dispatcher loop.
// It is a supervised background service so delivery never blocks the producer.
type Service struct {
	db             *database.DB
	client         *Client
	pollInterval   time.Duration
	outboxCapacity int
	now            func() time.Time
	backoff        func(attempt int) time.Duration
	logger         *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

// NewService builds a notification service over the panel database.
func NewService(db *database.DB, opts Options) *Service {
	client := opts.Client
	if client == nil {
		client = NewClient()
	}
	poll := opts.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	capacity := opts.OutboxCapacity
	if capacity <= 0 {
		capacity = defaultOutboxCap
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	backoff := opts.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}
	return &Service{
		db:             db,
		client:         client,
		pollInterval:   poll,
		outboxCapacity: capacity,
		now:            now,
		backoff:        backoff,
		logger:         slog.Default().With("component", "notifications"),
	}
}

func defaultBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Second << uint(attempt-1)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}

// PublishResult reports what happened to a producer's event.
type PublishResult struct {
	EventID  string
	Status   string
	Inserted bool
}

// Publish records one authoritative event. A repeated EventKey is a no-op.
// The event is always durable history; delivery is suppressed when external
// delivery is disabled, the category is off, or the severity is below the
// administrator's threshold.
func (s *Service) Publish(ctx context.Context, event models.NotificationEvent) (PublishResult, error) {
	if s.db == nil {
		return PublishResult{}, errors.New("notification store is not configured")
	}
	now := s.now()
	event.Normalize(now)
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if err := validatePublishEvent(event); err != nil {
		return PublishResult{}, err
	}

	settings, err := s.LoadSettings(ctx)
	if err != nil {
		return PublishResult{}, err
	}

	force := event.Category == models.NotificationCategoryNotificationTest
	status, reason := deliveryDecision(settings, event, force)

	inserted, finalStatus, err := s.db.InsertNotificationEvent(ctx, database.NotificationEnqueue{
		Event:          event,
		Status:         status,
		SuppressReason: reason,
		MaxAttempts:    settings.MaxAttempts,
		Force:          force,
		Cooldown:       time.Duration(settings.CooldownSeconds) * time.Second,
		Capacity:       s.outboxCapacity,
	})
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{EventID: event.ID, Status: finalStatus, Inserted: inserted}, nil
}

func validatePublishEvent(event models.NotificationEvent) error {
	if event.EventKey == "" {
		return errors.New("notification event key is required")
	}
	if event.Type == "" {
		return errors.New("notification event type is required")
	}
	if event.Summary == "" {
		return errors.New("notification event summary is required")
	}
	if !event.Category.Valid() && event.Category != models.NotificationCategoryNotificationTest {
		return fmt.Errorf("unknown notification category %q", event.Category)
	}
	if !event.Severity.Valid() {
		return fmt.Errorf("unknown notification severity %q", event.Severity)
	}
	return nil
}

func deliveryDecision(settings models.NotificationSettings, event models.NotificationEvent, force bool) (string, string) {
	switch {
	case force:
		// An explicit administrator test bypasses the disabled switch and
		// category filters. It is the only path that may send while disabled.
		return models.NotificationDeliveryPending, ""
	case event.Silent:
		return models.NotificationDeliverySuppressed, "history_only"
	case !settings.Enabled:
		return models.NotificationDeliverySuppressed, "disabled"
	case !settings.CategoryEnabled(event.Category):
		return models.NotificationDeliverySuppressed, "category_disabled"
	case event.Severity.Rank() < settings.MinSeverity.Rank():
		return models.NotificationDeliverySuppressed, "below_min_severity"
	case strings.TrimSpace(settings.URL) == "" || strings.TrimSpace(settings.AppToken) == "":
		return models.NotificationDeliverySuppressed, "not_configured"
	default:
		return models.NotificationDeliveryPending, ""
	}
}

// LoadSettings reads the persisted policy. An absent row is the disabled
// default, never an enabled destination.
func (s *Service) LoadSettings(ctx context.Context) (models.NotificationSettings, error) {
	settings := models.DefaultNotificationSettings()
	if s.db == nil {
		return settings, nil
	}
	var stored models.NotificationSettings
	if err := s.db.GetSetting(ctx, "notifications", &stored); err != nil {
		return settings, fmt.Errorf("load notification settings: %w", err)
	}
	if stored.MinSeverity == "" && stored.URL == "" && stored.MaxAttempts == 0 && stored.Categories == nil {
		return settings, nil
	}
	stored.Normalize()
	return stored, nil
}

// SendTest emits one durable test event and returns its event ID. The caller
// waits for the dispatcher to record a terminal outcome; nothing is fabricated.
func (s *Service) SendTest(ctx context.Context, summary, detail string) (string, error) {
	settings, err := s.LoadSettings(ctx)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(settings.URL) == "" || strings.TrimSpace(settings.AppToken) == "" {
		return "", errors.New("configure and save a gotify URL and application token before testing")
	}
	if _, err := ValidateEndpoint(settings.URL); err != nil {
		return "", err
	}
	now := s.now()
	result, err := s.Publish(ctx, models.NotificationEvent{
		EventKey:   "notification.test:" + uuid.NewString(),
		IncidentID: "notification.test:" + now.UTC().Format("20060102T150405"),
		Category:   models.NotificationCategoryNotificationTest,
		Severity:   models.NotificationSeverityInfo,
		Type:       "notification.test",
		EntityType: "settings",
		EntityID:   "notifications",
		Transition: "test",
		Summary:    summary,
		Detail:     detail,
		OccurredAt: now,
	})
	if err != nil {
		return "", err
	}
	return result.EventID, nil
}

// WaitForDelivery polls the durable outcome until the delivery reaches a
// terminal state or the context expires.
func (s *Service) WaitForDelivery(ctx context.Context, eventID string, interval time.Duration) (models.NotificationDelivery, error) {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		delivery, err := s.db.GetNotificationDeliveryByEventID(ctx, eventID)
		if err != nil {
			return delivery, err
		}
		if isTerminalDelivery(delivery) {
			return delivery, nil
		}
		select {
		case <-ctx.Done():
			return delivery, ctx.Err()
		case <-ticker.C:
		}
	}
}

func isTerminalDelivery(delivery models.NotificationDelivery) bool {
	switch delivery.Status {
	case models.NotificationDeliverySent, models.NotificationDeliveryFailed,
		models.NotificationDeliverySuppressed, models.NotificationDeliveryDropped:
		return true
	case models.NotificationDeliveryUncertain:
		// A transport failure is uncertain while retries remain; once attempts
		// are exhausted it is the truthful terminal outcome.
		return delivery.Attempts >= delivery.MaxAttempts
	default:
		return false
	}
}

// Name implements service.BackgroundService.
func (s *Service) Name() string { return "notifications" }

// Start implements service.BackgroundService and runs until ctx is canceled.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("notification service is already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		close(s.done)
		s.mu.Unlock()
	}()

	if err := s.db.RequeueStaleNotificationDeliveries(runCtx); err != nil {
		s.logger.Warn("Could not requeue stale notification deliveries", "err", err)
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		if runCtx.Err() != nil {
			return nil
		}
		s.drain(runCtx)
		select {
		case <-runCtx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Stop implements service.BackgroundService.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	running := s.running
	s.mu.Unlock()
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

func (s *Service) drain(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	settings, err := s.LoadSettings(ctx)
	if err != nil {
		s.logger.Warn("Could not load notification settings", "err", err)
		return
	}
	includeNonForced := settings.Enabled && strings.TrimSpace(settings.URL) != "" && strings.TrimSpace(settings.AppToken) != ""

	due, err := s.db.DueNotificationDispatch(ctx, s.now(), 20, includeNonForced)
	if err != nil {
		s.logger.Warn("Could not read notification outbox", "err", err)
		return
	}
	for _, dispatch := range due {
		if ctx.Err() != nil {
			return
		}
		s.deliver(ctx, settings, dispatch)
	}
}

func (s *Service) deliver(ctx context.Context, settings models.NotificationSettings, dispatch models.NotificationDispatch) {
	if !dispatch.Force && !settings.Enabled {
		return
	}
	if err := s.db.MarkNotificationSending(ctx, dispatch.DeliveryID); err != nil {
		s.logger.Warn("Could not mark notification sending", "delivery_id", dispatch.DeliveryID, "err", err)
		return
	}

	attempts := dispatch.Attempts + 1
	sendCtx, cancel := context.WithTimeout(ctx, gotifyRequestTimeout)
	httpStatus, sendErr := s.client.Send(sendCtx, settings.URL, settings.AppToken, Message{
		Title:    dispatch.Event.Summary,
		Body:     composeMessage(dispatch.Event),
		Priority: Priority(dispatch.Event.Severity),
	})
	cancel()

	// Recording the outcome must survive a shutdown that began while the HTTP
	// request was in flight; losing it would leave a sent message pending and
	// replay it after restart.
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer writeCancel()

	if sendErr == nil {
		if err := s.db.MarkNotificationSent(writeCtx, dispatch.DeliveryID, attempts, httpStatus); err != nil {
			s.logger.Warn("Could not record notification delivery", "delivery_id", dispatch.DeliveryID, "err", err)
		}
		return
	}

	s.recordDeliveryFailure(writeCtx, dispatch, attempts, httpStatus, sendErr)
}

func (s *Service) recordDeliveryFailure(ctx context.Context, dispatch models.NotificationDispatch, attempts, httpStatus int, sendErr error) {
	status := models.NotificationDeliveryPending
	if httpStatus == 0 {
		// No answer from Gotify is an uncertain outcome, not a confirmed
		// rejection and not a confirmed delivery.
		status = models.NotificationDeliveryUncertain
	}
	terminal := IsPermanent(sendErr) || attempts >= dispatch.MaxAttempts
	if terminal {
		status = models.NotificationDeliveryFailed
		if httpStatus == 0 {
			status = models.NotificationDeliveryUncertain
		}
	}
	next := s.now()
	if !terminal {
		next = next.Add(s.backoff(attempts))
	}
	reason := FormatAttemptReason(sendErr)
	if err := s.db.MarkNotificationRetry(ctx, dispatch.DeliveryID, attempts, dispatch.MaxAttempts, next, status, reason, httpStatus); err != nil {
		s.logger.Warn("Could not record notification failure", "delivery_id", dispatch.DeliveryID, "err", err)
	}
}

func composeMessage(event models.NotificationEvent) string {
	parts := make([]string, 0, 4)
	if event.Detail != "" {
		parts = append(parts, event.Detail)
	}
	if event.Transition != "" {
		parts = append(parts, "Transition: "+event.Transition)
	}
	if entity := strings.TrimSpace(event.EntityType + " " + event.EntityID); entity != "" {
		parts = append(parts, "Entity: "+entity)
	}
	if event.Evidence != "" {
		parts = append(parts, "Evidence: "+event.Evidence)
	}
	if len(parts) == 0 {
		return event.Summary
	}
	return strings.Join(parts, "\n")
}
