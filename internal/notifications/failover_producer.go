package notifications

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	failoverOutcomeBuffer    = 256
	defaultFailoverRetries   = 5
	failoverRetryShutdownCap = 2 * time.Second
)

// FailoverProducer accepts non-blocking failover outcomes from the VPN data
// plane and publishes them from its own worker. The data-plane caller may hold
// its service lock, so this type never performs I/O on the caller's goroutine.
type transitionPublisher interface {
	PublishTransition(ctx context.Context, transitions []database.NotificationTransition, event models.NotificationEvent) (PublishResult, error)
}

type FailoverProducer struct {
	db          notificationStateStore
	notifier    transitionPublisher
	outcomes    chan models.FailoverOutcome
	maxAttempts int
	backoff     func(attempt int) time.Duration
	logger      *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

// FailoverProducerOption configures retry policy, primarily for deterministic
// tests.
type FailoverProducerOption func(*FailoverProducer)

// WithFailoverRetry bounds transient persistence retries and their backoff.
func WithFailoverRetry(maxAttempts int, backoff func(int) time.Duration) FailoverProducerOption {
	return func(p *FailoverProducer) {
		if maxAttempts > 0 {
			p.maxAttempts = maxAttempts
		}
		if backoff != nil {
			p.backoff = backoff
		}
	}
}

// NewFailoverProducer builds the Phase 5 producer.
func NewFailoverProducer(db notificationStateStore, notifier transitionPublisher, opts ...FailoverProducerOption) *FailoverProducer {
	producer := &FailoverProducer{
		db:          db,
		notifier:    notifier,
		outcomes:    make(chan models.FailoverOutcome, failoverOutcomeBuffer),
		maxAttempts: defaultFailoverRetries,
		backoff:     defaultFailoverRetryBackoff,
		logger:      slog.Default().With("component", "notification-failover-producer"),
	}
	for _, opt := range opts {
		opt(producer)
	}
	return producer
}

func defaultFailoverRetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Second << uint(attempt-1)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return delay
}

// NotifyFailoverOutcome implements the VPN service's notifier interface. It is
// non-blocking: a saturated buffer drops the outcome with a log line rather than
// stalling failover or the health probe that called it.
func (p *FailoverProducer) NotifyFailoverOutcome(outcome models.FailoverOutcome) {
	if p == nil || outcome.SourceTunnelID == 0 {
		return
	}
	select {
	case p.outcomes <- outcome:
	default:
		p.logger.Error("Failover notification buffer is full; outcome not recorded",
			"tunnel_id", outcome.SourceTunnelID, "decision", outcome.Decision)
	}
}

// Name implements service.BackgroundService.
func (p *FailoverProducer) Name() string { return "notification-failover-producer" }

// Start implements service.BackgroundService.
func (p *FailoverProducer) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return errors.New("failover notification producer is already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	p.running = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.running = false
		close(p.done)
		p.mu.Unlock()
	}()

	queue := make([]failoverWork, 0, 16)
	for {
		if len(queue) == 0 {
			select {
			case <-runCtx.Done():
				p.drainOnShutdown(queue)
				return nil
			case outcome := <-p.outcomes:
				queue = append(queue, failoverWork{outcome: outcome})
			}
		}
		work := &queue[0]
		done, delay := p.processWork(runCtx, work)
		if done {
			queue = queue[1:]
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-runCtx.Done():
			timer.Stop()
			p.drainOnShutdown(queue)
			return nil
		case <-timer.C:
		}
	}
}

type failoverWork struct {
	outcome  models.FailoverOutcome
	attempts int
}

func (p *FailoverProducer) processWork(ctx context.Context, work *failoverWork) (done bool, delay time.Duration) {
	err := p.publish(ctx, work.outcome)
	if err == nil {
		return true, 0
	}
	work.attempts++
	if work.attempts >= p.maxAttempts {
		p.logger.Error("Failover notification dropped after bounded retries",
			"tunnel_id", work.outcome.SourceTunnelID, "decision", work.outcome.Decision,
			"attempts", work.attempts, "err", err)
		return true, 0
	}
	return false, p.backoff(work.attempts)
}

// drainOnShutdown makes one bounded attempt for queued outcomes after the worker
// stops accepting new work. Anything still failing is logged as lost: these are
// in-memory observations and are not durable across a process restart.
func (p *FailoverProducer) drainOnShutdown(queue []failoverWork) {
	for {
		select {
		case outcome := <-p.outcomes:
			queue = append(queue, failoverWork{outcome: outcome})
			continue
		default:
		}
		break
	}
	if len(queue) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), failoverRetryShutdownCap)
	defer cancel()
	lost := 0
	for _, work := range queue {
		if err := p.publish(ctx, work.outcome); err != nil {
			lost++
		}
	}
	if lost > 0 {
		p.logger.Error("Failover notifications lost at shutdown",
			"lost", lost, "queued", len(queue), "reason", "database unavailable or deadline exceeded")
	}
}

// Stop implements service.BackgroundService. Outcomes still buffered when the
// panel stops are lost; they are in-memory observations, not durable facts.
func (p *FailoverProducer) Stop(ctx context.Context) error {
	p.mu.Lock()
	cancel := p.cancel
	done := p.done
	running := p.running
	p.mu.Unlock()
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

func (p *FailoverProducer) publish(ctx context.Context, outcome models.FailoverOutcome) error {
	if p.db == nil || p.notifier == nil {
		return errors.New("failover producer is not configured")
	}
	state := fmt.Sprintf("%s:%d:%d:%d", outcome.Decision, outcome.Migrated, outcome.Stranded, outcome.StateVersion)
	entityKey := fmt.Sprintf("%d", outcome.SourceTunnelID)
	for attempt := 0; attempt < 2; attempt++ {
		done, err := p.tryPublishFailover(ctx, outcome, state, entityKey)
		if done {
			return err
		}
	}
	return errors.New("failover transition remained stale after retry")
}

func (p *FailoverProducer) tryPublishFailover(ctx context.Context, outcome models.FailoverOutcome, state, entityKey string) (bool, error) {
	previous, generation, found, err := p.db.ReadNotificationProducerState(ctx, "failover", entityKey)
	if err != nil {
		return true, err
	}
	if found && previous == state {
		return true, nil
	}
	event, ok := failoverEvent(outcome, state, time.Now())
	if !ok {
		return true, nil
	}
	if !found {
		previous = ""
		generation = 0
	}
	event.EventKey = TransitionEventKey("failover", entityKey, generation+1, state)
	_, err = p.notifier.PublishTransition(ctx, []database.NotificationTransition{{
		Producer:           "failover",
		EntityKey:          entityKey,
		PreviousState:      previous,
		ExpectedGeneration: generation,
		State:              state,
	}}, event)
	if errors.Is(err, database.ErrNotificationTransitionStale) {
		return false, nil
	}
	return true, err
}

func failoverEvent(outcome models.FailoverOutcome, state string, now time.Time) (models.NotificationEvent, bool) {
	event := models.NotificationEvent{
		EventKey:   fmt.Sprintf("failover:%d:%s", outcome.SourceTunnelID, state),
		IncidentID: fmt.Sprintf("backend:%d", outcome.SourceTunnelID),
		Category:   models.NotificationCategoryFailover,
		EntityType: "backend",
		EntityID:   fmt.Sprintf("%d", outcome.SourceTunnelID),
		Transition: outcome.Decision,
		OccurredAt: now,
	}
	switch outcome.Decision {
	case "no_target":
		event.Severity = models.NotificationSeverityCritical
		event.Type = "failover.no_target"
		event.Summary = "Failover found no eligible backend"
		event.Detail = "No healthy backend of the same protocol family was eligible. Sessions may remain on the failed backend; no purchase or replacement was authorized."
		event.Evidence = "authoritative failover attempt reported no target"
		return event, true
	case "partial":
		event.Severity = models.NotificationSeverityCritical
		event.Type = "failover.partial"
		event.Summary = "Failover left sessions stranded"
		event.Detail = fmt.Sprintf("%d session(s) moved and %d remained on the failed backend.", outcome.Migrated, outcome.Stranded)
		event.Evidence = "authoritative failover result"
		return event, true
	case "success":
		event.Severity = models.NotificationSeverityInfo
		event.Type = "failover.succeeded"
		event.Summary = "Failover moved established sessions"
		event.Detail = fmt.Sprintf("%d session(s) moved to a healthy compatible backend.", outcome.Migrated)
		event.Evidence = "authoritative failover result"
		event.Silent = outcome.Manual
		return event, true
	default:
		return models.NotificationEvent{}, false
	}
}
