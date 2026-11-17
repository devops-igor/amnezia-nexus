package notifications

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const defaultObserverInterval = 30 * time.Second

// ObserverOptions configure the periodic authoritative-state observer.
type ObserverOptions struct {
	Interval time.Duration
	Now      func() time.Time
}

// Observer watches authoritative server and backend state and publishes only
// durable transitions. It is deliberately an observer, not a second monitor:
// reachability comes from the existing probe cache and backend health comes from
// the persisted backend tunnel rows.
type Observer struct {
	db        *database.DB
	notifier  *Service
	interval  time.Duration
	now       func() time.Time
	startedAt time.Time
	logger    *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

// NewObserver builds the Phase 2 observer.
func NewObserver(db *database.DB, notifier *Service, opts ObserverOptions) *Observer {
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultObserverInterval
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Observer{
		db:        db,
		notifier:  notifier,
		interval:  interval,
		now:       now,
		startedAt: now(),
		logger:    slog.Default().With("component", "notification-observer"),
	}
}

// Name implements service.BackgroundService.
func (o *Observer) Name() string { return "notification-observer" }

// Start implements service.BackgroundService.
func (o *Observer) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return errors.New("notification observer is already running")
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
			o.logger.Warn("Notification observation pass failed", "err", err)
		}
		select {
		case <-runCtx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Stop implements service.BackgroundService.
func (o *Observer) Stop(ctx context.Context) error {
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

// ObserveOnce runs one observation pass. It is exported so tests and future
// producers can drive the same code without waiting for the ticker.
func (o *Observer) ObserveOnce(ctx context.Context) error {
	if o.db == nil || o.notifier == nil {
		return errors.New("notification observer is not configured")
	}
	observers := []func(context.Context) error{
		o.observeServers,
		o.observeBackends,
		o.observeProtocolCapacity,
		o.observeProvisioning,
	}
	var errs []error
	for _, observe := range observers {
		if err := observe(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// publishObservedState reads the durable producer state and either records a
// baseline or commits the state change together with its event. firstObservation
// allows a newly created entity (not a historical row after restart) to announce
// an already-terminal state.
func (o *Observer) publishObservedState(
	ctx context.Context,
	producer, entityKey, state string,
	firstObservation bool,
	build func(previous string) (models.NotificationEvent, bool),
) error {
	previous, generation, found, err := o.db.ReadNotificationProducerState(ctx, producer, entityKey)
	if err != nil {
		return err
	}
	if !found {
		if !firstObservation {
			return o.recordStateBaseline(ctx, producer, entityKey, state)
		}
		event, ok := build("")
		if !ok {
			return o.recordStateBaseline(ctx, producer, entityKey, state)
		}
		event.EventKey = TransitionEventKey(producer, entityKey, 1, state)
		_, err = o.notifier.PublishTransition(ctx, []database.NotificationTransition{{
			Producer: producer, EntityKey: entityKey, State: state,
		}}, event)
		if errors.Is(err, database.ErrNotificationTransitionStale) {
			return nil
		}
		return err
	}
	if previous == state {
		return nil
	}
	event, ok := build(previous)
	if !ok {
		return o.recordStateBaseline(ctx, producer, entityKey, state)
	}
	event.EventKey = TransitionEventKey(producer, entityKey, generation+1, state)
	_, err = o.notifier.PublishTransition(ctx, []database.NotificationTransition{{
		Producer:           producer,
		EntityKey:          entityKey,
		PreviousState:      previous,
		ExpectedGeneration: generation,
		State:              state,
	}}, event)
	if errors.Is(err, database.ErrNotificationTransitionStale) {
		return nil
	}
	return err
}

func (o *Observer) recordStateBaseline(ctx context.Context, producer, entityKey, state string) error {
	_, _, err := o.db.AdvanceNotificationProducerState(ctx, producer, entityKey, state)
	return err
}

func (o *Observer) observeProvisioning(ctx context.Context) error {
	var errs []error
	if err := o.observeOrders(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := o.observeSetupIntents(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (o *Observer) observeOrders(ctx context.Context) error {
	orders, err := o.db.ListGigahostOrders(ctx)
	if err != nil {
		return fmt.Errorf("fetch gigahost orders for notifications: %w", err)
	}
	cutoff, err := o.provisioningBaseline(ctx)
	if err != nil {
		return err
	}
	for _, order := range orders {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := o.observeOrder(ctx, order, cutoff); err != nil {
			return err
		}
	}
	return nil
}

func (o *Observer) observeOrder(ctx context.Context, order models.GigahostOrder, cutoff time.Time) error {
	if strings.TrimSpace(order.OrderID) == "" {
		return nil
	}
	state := strings.ToLower(strings.TrimSpace(order.Status))
	if state == "" {
		return nil
	}
	return o.publishObservedState(ctx, "gigahost_order", order.OrderID, state, !order.CreatedAt.IsZero() && !order.CreatedAt.Before(cutoff),
		func(previous string) (models.NotificationEvent, bool) {
			return orderTransitionEvent(order, previous, state, o.now())
		})
}

// provisioningBaseline is the durable cutoff between historical ledger rows and
// orders/jobs created while notifications were active. It survives a restart, so
// a failed event insert can still be announced on the next pass instead of being
// reclassified as history.
func (o *Observer) provisioningBaseline(ctx context.Context) (time.Time, error) {
	state, _, found, err := o.db.ReadNotificationProducerState(ctx, "observer_meta", "provisioning_baseline")
	if err != nil {
		return time.Time{}, err
	}
	if found {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, state); parseErr == nil {
			return parsed.UTC(), nil
		}
	}
	cutoff := o.startedAt.UTC()
	if _, _, err := o.db.AdvanceNotificationProducerState(ctx, "observer_meta", "provisioning_baseline", cutoff.Format(time.RFC3339Nano)); err != nil {
		return time.Time{}, err
	}
	return cutoff, nil
}

func (o *Observer) observeSetupIntents(ctx context.Context) error {
	intents, err := o.db.ListGigahostSetupIntents(ctx)
	if err != nil {
		return fmt.Errorf("fetch gigahost setup intents for notifications: %w", err)
	}
	cutoff, err := o.provisioningBaseline(ctx)
	if err != nil {
		return err
	}
	for _, intent := range intents {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := o.observeSetupIntent(ctx, intent, cutoff); err != nil {
			return err
		}
	}
	return nil
}

func (o *Observer) observeSetupIntent(ctx context.Context, intent models.GigahostSetupIntent, cutoff time.Time) error {
	if strings.TrimSpace(intent.OrderID) == "" {
		return nil
	}
	state := setupObservationState(intent)
	return o.publishObservedState(ctx, "gigahost_setup", intent.OrderID, state, !intent.CreatedAt.IsZero() && !intent.CreatedAt.Before(cutoff),
		func(previous string) (models.NotificationEvent, bool) {
			return setupTransitionEvent(intent, previous, state, o.now())
		})
}

func orderTransitionEvent(order models.GigahostOrder, previous, state string, now time.Time) (models.NotificationEvent, bool) {
	event := models.NotificationEvent{
		EventKey:   transitionEventKeyString("gigahost_order", order.OrderID, state, now),
		IncidentID: "order:" + order.OrderID,
		Category:   models.NotificationCategoryProvisioning,
		EntityType: "order",
		EntityID:   order.OrderID,
		Transition: previous + "->" + state,
		OccurredAt: now,
	}
	switch state {
	case "failed":
		event.Severity = models.NotificationSeverityWarning
		event.Type = "order.failed"
		event.Summary = "Gigahost order failed"
		event.Detail = "The provider reported a terminal order failure. The order and any VPS are kept; nothing is retried automatically."
		event.Evidence = "order status " + previous + " -> " + state
		return event, true
	case "unknown":
		event.Severity = models.NotificationSeverityCritical
		event.Type = "order.outcome_unknown"
		event.Summary = "Gigahost order outcome is unknown"
		event.Detail = "The provider outcome could not be confirmed and automation was stopped safely. This is not a failure and no second order is placed."
		event.Evidence = "order status " + previous + " -> " + state
		return event, true
	case "ready":
		event.Severity = models.NotificationSeverityInfo
		event.Type = "order.provider_ready"
		event.Summary = "Gigahost VPS is ready"
		event.Detail = "The provider reported the VPS ready. Provider readiness is not backend health; setup and traffic qualification are separate facts."
		event.Evidence = "order status " + previous + " -> " + state
		return event, true
	default:
		return models.NotificationEvent{}, false
	}
}

func setupObservationState(intent models.GigahostSetupIntent) string {
	if intent.HostMismatch {
		return "host_mismatch"
	}
	state := strings.ToLower(strings.TrimSpace(intent.State))
	if state == models.SetupStateInstallPaused && strings.TrimSpace(intent.Step) != "" {
		return state + ":" + strings.ToLower(strings.TrimSpace(intent.Step))
	}
	return state
}

func setupTransitionEvent(intent models.GigahostSetupIntent, previous, state string, now time.Time) (models.NotificationEvent, bool) {
	event := models.NotificationEvent{
		EventKey:   transitionEventKeyString("gigahost_setup", intent.OrderID, state, now),
		IncidentID: "order:" + intent.OrderID,
		Category:   models.NotificationCategoryProvisioning,
		EntityType: "setup",
		EntityID:   intent.OrderID,
		Transition: previous + "->" + state,
		OccurredAt: now,
	}
	if setupAttentionEvent(&event, previous, state) {
		return event, true
	}
	if setupCompletionEvent(&event, previous, state) {
		return event, true
	}
	// pending/installing are progress, not notifications.
	return models.NotificationEvent{}, false
}

func setupAttentionEvent(event *models.NotificationEvent, previous, state string) bool {
	event.Evidence = "setup state " + previous + " -> " + state
	switch state {
	case "host_mismatch":
		event.Severity = models.NotificationSeverityCritical
		event.Type = "setup.host_mismatch"
		event.Summary = "Gigahost setup stopped on an SSH host identity mismatch"
		event.Detail = "The observed host identity contradicts the trusted identity for this order. Automation stopped for security; no further remote commands follow."
		event.Evidence = "host identity mismatch recorded on the setup intent"
		return true
	case models.SetupStateAwaitingHostConfirm:
		event.Severity = models.NotificationSeverityWarning
		event.Type = "setup.awaiting_host_confirmation"
		event.Summary = "Gigahost setup needs host confirmation"
		event.Detail = "The provider VPS is provisioned but its SSH host identity is not trusted yet. This manual workflow needs an administrator decision."
		return true
	case models.SetupStateAwaitingCredentials:
		event.Severity = models.NotificationSeverityWarning
		event.Type = "setup.awaiting_credentials"
		event.Summary = "Gigahost setup needs credentials"
		event.Detail = "The provider VPS is ready but no usable credential reference exists. Supply credentials through the documented manual workflow."
		return true
	case models.SetupStateFailed:
		event.Severity = models.NotificationSeverityCritical
		event.Type = "setup.failed"
		event.Summary = "Gigahost setup failed"
		event.Detail = "Setup could not continue. The durable stop reason is recorded on the setup intent; no effects are replayed."
		return true
	default:
		if !strings.HasPrefix(state, models.SetupStateInstallPaused) {
			return false
		}
		event.Severity = models.NotificationSeverityCritical
		event.Type = "setup.paused"
		event.Summary = "Gigahost setup paused with an unproven outcome"
		event.Detail = "An install attempt stopped without a proven result. Nothing is retried automatically; resume only after verifying the recorded step."
		return true
	}
}

func setupCompletionEvent(event *models.NotificationEvent, previous, state string) bool {
	event.Evidence = "setup state " + previous + " -> " + state
	switch state {
	case models.SetupStateReady:
		event.Severity = models.NotificationSeverityInfo
		event.Type = "setup.ready"
		event.Recovery = previous == models.SetupStateInstallPaused ||
			previous == models.SetupStateFailed ||
			strings.HasPrefix(previous, models.SetupStateInstallPaused)
		event.Summary = "Gigahost setup completed"
		event.Detail = "The selected protocol was installed and the backend was admitted only after real traffic qualification."
		return true
	case models.SetupStateCanceled:
		event.Severity = models.NotificationSeverityInfo
		event.Type = "setup.canceled"
		event.Silent = true
		event.Summary = "Gigahost setup approval was canceled"
		event.Detail = "An administrator explicitly canceled this setup. No further panel effects follow."
		return true
	default:
		return false
	}
}

func transitionEventKeyString(producer, entityKey, state string, now time.Time) string {
	return fmt.Sprintf("%s:%s:%s:%d", producer, entityKey, state, now.UTC().UnixNano())
}

func (o *Observer) observeServers(ctx context.Context) error {
	servers, err := o.db.GetAllServers(ctx)
	if err != nil {
		return fmt.Errorf("fetch servers for notifications: %w", err)
	}
	for _, server := range servers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := o.observeServer(ctx, server); err != nil {
			return err
		}
	}
	return nil
}

func (o *Observer) observeServer(ctx context.Context, server models.Server) error {
	status, err := o.db.GetServerStatus(ctx, server.ID)
	if err != nil {
		return fmt.Errorf("read server %d reachability: %w", server.ID, err)
	}
	if status == models.ReachabilityUnknown {
		// A missing cache (including every restart) is not evidence of an
		// outage. Wait for an authoritative probe result.
		return nil
	}
	return o.publishObservedState(ctx, "server_reachability", fmt.Sprintf("%d", server.ID), string(status), false,
		func(previous string) (models.NotificationEvent, bool) {
			return serverTransitionEvent(server, previous, status, o.now())
		})
}

func serverTransitionEvent(server models.Server, previous string, status models.ReachabilityStatus, now time.Time) (models.NotificationEvent, bool) {
	state := string(status)
	event := models.NotificationEvent{
		EventKey:   transitionEventKey("server_reachability", server.ID, state, now),
		IncidentID: fmt.Sprintf("server:%d:reachability", server.ID),
		Category:   models.NotificationCategoryServerHealth,
		Type:       "server.reachability." + state,
		EntityType: "server",
		EntityID:   fmt.Sprintf("%d", server.ID),
		Transition: previous + "->" + state,
		OccurredAt: now,
	}
	switch {
	case previous == string(models.ReachabilityOnline) && status == models.ReachabilityOffline:
		event.Severity = models.NotificationSeverityCritical
		event.Summary = fmt.Sprintf("Server %s is offline", server.Name)
		event.Detail = "Sustained authoritative reachability checks report the server offline."
		return event, true
	case previous == string(models.ReachabilityOffline) && status == models.ReachabilityOnline:
		event.Severity = models.NotificationSeverityInfo
		event.Recovery = true
		event.Summary = fmt.Sprintf("Server %s is online again", server.Name)
		event.Detail = "A fresh authoritative reachability probe confirmed the server is online."
		return event, true
	default:
		// Online<->unknown and offline<->unknown are monitoring uncertainty,
		// never a confirmed outage or recovery.
		return models.NotificationEvent{}, false
	}
}

func (o *Observer) observeBackends(ctx context.Context) error {
	tunnels, err := o.db.GetBackendTunnels(ctx)
	if err != nil {
		return fmt.Errorf("fetch backend tunnels for notifications: %w", err)
	}
	for _, tunnel := range tunnels {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		state := classifyBackendState(tunnel)
		err := o.publishObservedState(ctx, "backend_health", fmt.Sprintf("%d", tunnel.ID), state, false,
			func(previous string) (models.NotificationEvent, bool) {
				return backendTransitionEvent(tunnel, previous, state, o.now())
			})
		if err != nil {
			return err
		}
	}
	return nil
}

func classifyBackendState(tunnel models.BackendTunnel) string {
	if !tunnel.Enabled {
		// Administrative intent, not a health incident. Recording a distinct
		// state prevents re-enabling from being reported as an incident recovery.
		return "admin_disabled"
	}
	status := strings.ToLower(strings.TrimSpace(tunnel.Status))
	switch status {
	case models.TunnelStatusActive, models.TunnelStatusDegraded, models.TunnelStatusHandshakeBlocked:
		return status
	case models.TunnelStatusDisabled:
		if strings.EqualFold(tunnel.DisableReason, models.DisableReasonHealth) {
			return "disabled:health"
		}
		return "admin_disabled"
	default:
		return status
	}
}

func backendTransitionEvent(tunnel models.BackendTunnel, previous, state string, now time.Time) (models.NotificationEvent, bool) {
	event := models.NotificationEvent{
		EventKey:   transitionEventKey("backend_health", tunnel.ID, state, now),
		IncidentID: fmt.Sprintf("backend:%d", tunnel.ID),
		Category:   models.NotificationCategoryBackendHealth,
		EntityType: "backend",
		EntityID:   fmt.Sprintf("%d", tunnel.ID),
		Transition: previous + "->" + state,
		OccurredAt: now,
	}
	if backendFailureEvent(&event, tunnel.ID, previous, state) {
		return event, true
	}
	if backendRecovered(previous, state) {
		event.Severity = models.NotificationSeverityInfo
		event.Recovery = true
		event.Type = "backend.recovered"
		event.Summary = fmt.Sprintf("VPN backend %d recovered", tunnel.ID)
		event.Detail = "A fresh authoritative health check returned the backend to active service."
		event.Evidence = "backend status " + previous + " -> " + state
		return event, true
	}
	// Administrative disable/enable, connecting and unknown states are not
	// incidents. A re-enabled backend does not inherit an incident recovery.
	return models.NotificationEvent{}, false
}

func backendFailureEvent(event *models.NotificationEvent, tunnelID int64, previous, state string) bool {
	event.Evidence = "backend status " + previous + " -> " + state
	switch state {
	case models.TunnelStatusHandshakeBlocked:
		if previous == models.TunnelStatusHandshakeBlocked {
			return false
		}
		event.Severity = models.NotificationSeverityWarning
		event.Type = "backend.handshake_blocked"
		event.Summary = fmt.Sprintf("VPN backend %d cannot complete a handshake", tunnelID)
		event.Detail = "The authoritative health probe reports a blocked outer handshake. Existing sessions may still be carried; this is not proof of a network ban."
		return true
	case "disabled:health":
		if previous == "disabled:health" {
			return false
		}
		event.Severity = models.NotificationSeverityCritical
		event.Type = "backend.health_disabled"
		event.Summary = fmt.Sprintf("VPN backend %d was disabled by health checks", tunnelID)
		event.Detail = "The backend failed sustained authoritative health checks and was removed from eligible capacity."
		return true
	case models.TunnelStatusDegraded:
		if previous == models.TunnelStatusDegraded {
			return false
		}
		event.Severity = models.NotificationSeverityWarning
		event.Type = "backend.degraded"
		event.Summary = fmt.Sprintf("VPN backend %d is degraded", tunnelID)
		event.Detail = "Authoritative health checks report degraded performance."
		return true
	default:
		return false
	}
}

func backendRecovered(previous, state string) bool {
	if state != models.TunnelStatusActive {
		return false
	}
	return previous == models.TunnelStatusHandshakeBlocked ||
		previous == "disabled:health" ||
		previous == models.TunnelStatusDegraded
}

func (o *Observer) observeProtocolCapacity(ctx context.Context) error {
	activeProtocols, err := o.db.GetActiveProtocols(ctx)
	if err != nil {
		return fmt.Errorf("fetch active protocols: %w", err)
	}
	if len(activeProtocols) == 0 {
		return nil
	}
	eligible, unknown, err := o.protocolEligibility(ctx)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(activeProtocols))
	for _, raw := range activeProtocols {
		protocol := models.NormalizeProtocol(raw)
		if seen[protocol] {
			continue
		}
		seen[protocol] = true
		if unknown[protocol] {
			// Startup/health state is not yet authoritative. A persisted
			// "available" must not turn into a false outage while probes settle.
			continue
		}
		if err := o.observeProtocol(ctx, protocol, eligible[protocol]); err != nil {
			return err
		}
	}
	return nil
}

func (o *Observer) observeProtocol(ctx context.Context, protocol string, hasEligible bool) error {
	state := "unavailable"
	if hasEligible {
		state = "available"
	}
	return o.publishObservedState(ctx, "protocol_capacity", protocol, state, false,
		func(previous string) (models.NotificationEvent, bool) {
			return protocolCapacityEvent(protocol, previous, state, o.now())
		})
}

func (o *Observer) protocolEligibility(ctx context.Context) (eligible map[string]bool, unknown map[string]bool, err error) {
	tunnels, err := o.db.GetBackendTunnels(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch protocol capacity: %w", err)
	}
	eligible = make(map[string]bool, len(tunnels))
	unknown = make(map[string]bool, len(tunnels))
	for _, tunnel := range tunnels {
		if !tunnel.Enabled {
			continue
		}
		protocol := models.NormalizeTunnelProtocol(tunnel.Protocol)
		status := strings.ToLower(strings.TrimSpace(tunnel.Status))
		switch status {
		case models.TunnelStatusActive:
			eligible[protocol] = true
		case "", "unknown", models.TunnelStatusConnecting:
			// Not an authoritative down state.
			unknown[protocol] = true
		}
	}
	return eligible, unknown, nil
}

func protocolCapacityEvent(protocol, previous, state string, now time.Time) (models.NotificationEvent, bool) {
	event := models.NotificationEvent{
		EventKey:   transitionEventKey("protocol_capacity", 0, protocol+":"+state, now),
		IncidentID: "protocol:" + protocol + ":capacity",
		Category:   models.NotificationCategoryBackendHealth,
		EntityType: "protocol",
		EntityID:   protocol,
		Transition: previous + "->" + state,
		OccurredAt: now,
	}
	switch {
	case state == "unavailable":
		event.Severity = models.NotificationSeverityCritical
		event.Type = "protocol.capacity_unavailable"
		event.Summary = fmt.Sprintf("No healthy %s backend remains", protocol)
		event.Detail = "Every enabled backend for an in-use protocol is unavailable. This is one aggregate alert, not one push per failed probe."
		event.Evidence = "enabled backend statuses contain no active tunnel for " + protocol
		return event, true
	case previous == "unavailable" && state == "available":
		event.Severity = models.NotificationSeverityInfo
		event.Recovery = true
		event.Type = "protocol.capacity_restored"
		event.Summary = fmt.Sprintf("%s backend capacity is restored", protocol)
		event.Detail = "At least one enabled backend for an in-use protocol is active again."
		event.Evidence = "an active " + protocol + " tunnel is available"
		return event, true
	default:
		return models.NotificationEvent{}, false
	}
}

func transitionEventKey(producer string, entityID int64, state string, now time.Time) string {
	return fmt.Sprintf("%s:%d:%s:%d", producer, entityID, state, now.UTC().UnixNano())
}
