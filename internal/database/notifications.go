package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// NotificationEnqueue carries one event and the policy decision the notification
// service already made. The store enforces idempotency, cooldown and outbox
// capacity inside one transaction so a repeated poll cannot insert twice and a
// saturated outbox cannot block the producer.
type NotificationEnqueue struct {
	Event          models.NotificationEvent
	Status         string
	SuppressReason string
	MaxAttempts    int
	Force          bool
	Cooldown       time.Duration
	Capacity       int
}

// InsertNotificationEvent durably records an event and its delivery state.
//
// It returns inserted=false when EventKey already exists: the caller's producer
// replay is a no-op, not a second notification. The returned status is the final
// delivery status after cooldown/capacity suppression.
func (d *DB) InsertNotificationEvent(ctx context.Context, req NotificationEnqueue) (bool, string, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := time.Now().UTC()
	event := req.Event
	event.Normalize(now)

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return false, "", fmt.Errorf("begin notification enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	inserted, err := insertNotificationEventRow(ctx, tx, event, now)
	if err != nil || !inserted {
		return inserted, "", err
	}
	status, reason, err := notificationDeliveryDecision(ctx, tx, req, event)
	if err != nil {
		return false, "", err
	}
	if err := insertNotificationDeliveryRow(ctx, tx, req, event.ID, status, reason, now); err != nil {
		return false, "", err
	}
	if err := tx.Commit(); err != nil {
		return false, "", fmt.Errorf("commit notification enqueue: %w", err)
	}
	return true, status, nil
}

func insertNotificationEventRow(ctx context.Context, tx *sql.Tx, event models.NotificationEvent, now time.Time) (bool, error) {
	recovery := 0
	if event.Recovery {
		recovery = 1
	}
	result, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO notification_events
			(id, event_key, incident_id, category, severity, event_type,
			 entity_type, entity_id, transition, summary, detail, evidence,
			 recovery, occurred_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.EventKey, event.IncidentID, string(event.Category),
		string(event.Severity), event.Type, event.EntityType, event.EntityID,
		event.Transition, event.Summary, event.Detail, event.Evidence,
		recovery, formatNotificationTime(event.OccurredAt), formatNotificationTime(now),
	)
	if err != nil {
		return false, fmt.Errorf("insert notification event: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count inserted notification event: %w", err)
	}
	return rows > 0, nil
}

func notificationDeliveryDecision(ctx context.Context, tx *sql.Tx, req NotificationEnqueue, event models.NotificationEvent) (string, string, error) {
	status := req.Status
	if status == "" {
		status = models.NotificationDeliveryPending
	}
	status, reason, err := applyNotificationCooldown(ctx, tx, req, event, status, req.SuppressReason)
	if err != nil {
		return "", "", err
	}
	status, reason, err = applyNotificationCapacity(ctx, tx, req, status, reason)
	if err != nil {
		return "", "", err
	}
	return status, reason, nil
}

func applyNotificationCooldown(ctx context.Context, tx *sql.Tx, req NotificationEnqueue, event models.NotificationEvent, status, reason string) (string, string, error) {
	if status != models.NotificationDeliveryPending || req.Cooldown <= 0 || event.Recovery || req.Force {
		return status, reason, nil
	}
	suppressed, err := notificationCooldownActive(ctx, tx, req.Cooldown, event)
	if err != nil {
		return "", "", err
	}
	if suppressed {
		return models.NotificationDeliverySuppressed, "cooldown", nil
	}
	return status, reason, nil
}

func applyNotificationCapacity(ctx context.Context, tx *sql.Tx, req NotificationEnqueue, status, reason string) (string, string, error) {
	if status != models.NotificationDeliveryPending || req.Capacity <= 0 {
		return status, reason, nil
	}
	full, err := notificationOutboxFull(ctx, tx, req.Capacity)
	if err != nil {
		return "", "", err
	}
	if full {
		return models.NotificationDeliveryDropped, "queue_full", nil
	}
	return status, reason, nil
}

func notificationCooldownActive(ctx context.Context, tx *sql.Tx, cooldown time.Duration, event models.NotificationEvent) (bool, error) {
	cooldownStart := event.OccurredAt.Add(-cooldown)
	var recent int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM notification_events
		WHERE incident_id = ? AND event_type = ? AND recovery = 0 AND id <> ?
		  AND julianday(occurred_at) >= julianday(?)`,
		event.IncidentID, event.Type, event.ID, formatNotificationTime(cooldownStart),
	).Scan(&recent)
	if err != nil {
		return false, fmt.Errorf("check notification cooldown: %w", err)
	}
	return recent > 0, nil
}

func notificationOutboxFull(ctx context.Context, tx *sql.Tx, capacity int) (bool, error) {
	var queued int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM notification_deliveries
		WHERE status IN (?, ?) OR (status = ? AND attempts < max_attempts)`,
		models.NotificationDeliveryPending, models.NotificationDeliverySending,
		models.NotificationDeliveryUncertain,
	).Scan(&queued)
	if err != nil {
		return false, fmt.Errorf("count notification outbox: %w", err)
	}
	return queued >= capacity, nil
}

func insertNotificationDeliveryRow(ctx context.Context, tx *sql.Tx, req NotificationEnqueue, eventID, status, reason string, now time.Time) error {
	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 6
	}
	force := 0
	if req.Force {
		force = 1
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO notification_deliveries
			(event_id, status, attempts, max_attempts, next_attempt_at,
			 last_error, last_http_status, force, created_at, updated_at)
		VALUES (?, ?, 0, ?, ?, ?, 0, ?, ?, ?)`,
		eventID, status, maxAttempts, formatNotificationTime(now), reason, force,
		formatNotificationTime(now), formatNotificationTime(now),
	)
	if err != nil {
		return fmt.Errorf("insert notification delivery: %w", err)
	}
	return nil
}

// DueNotificationDispatch returns delivery work ordered oldest first. When
// includeNonForced is false only explicit test deliveries are eligible, which is
// how disabled mode stays silent without discarding real events.
func (d *DB) DueNotificationDispatch(ctx context.Context, now time.Time, limit int, includeNonForced bool) ([]models.NotificationDispatch, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `
		SELECT d.id, d.attempts, d.max_attempts, d.force,
		       e.id, e.event_key, e.incident_id, e.category, e.severity,
		       e.event_type, e.entity_type, e.entity_id, e.transition,
		       e.summary, e.detail, e.evidence, e.recovery, e.occurred_at
		FROM notification_deliveries d
		JOIN notification_events e ON e.id = d.event_id
		WHERE (d.status IN (?, ?) OR (d.status = ? AND d.attempts < d.max_attempts))
		  AND julianday(d.next_attempt_at) <= julianday(?)`
	args := []any{
		models.NotificationDeliveryPending,
		models.NotificationDeliverySending,
		models.NotificationDeliveryUncertain,
		formatNotificationTime(now),
	}
	if !includeNonForced {
		query += ` AND d.force = 1`
	}
	query += ` ORDER BY d.id ASC LIMIT ?`
	args = append(args, limit)

	rows, err := d.sqlDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query due notifications: %w", err)
	}
	defer rows.Close()

	var out []models.NotificationDispatch
	for rows.Next() {
		var dispatch models.NotificationDispatch
		var force, recovery int
		var occurred string
		if err := rows.Scan(
			&dispatch.DeliveryID, &dispatch.Attempts, &dispatch.MaxAttempts, &force,
			&dispatch.Event.ID, &dispatch.Event.EventKey, &dispatch.Event.IncidentID,
			&dispatch.Event.Category, &dispatch.Event.Severity, &dispatch.Event.Type,
			&dispatch.Event.EntityType, &dispatch.Event.EntityID, &dispatch.Event.Transition,
			&dispatch.Event.Summary, &dispatch.Event.Detail, &dispatch.Event.Evidence,
			&recovery, &occurred,
		); err != nil {
			return nil, fmt.Errorf("scan due notification: %w", err)
		}
		dispatch.Force = force == 1
		dispatch.Event.Recovery = recovery == 1
		dispatch.Event.OccurredAt = parseNotificationTime(occurred)
		out = append(out, dispatch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due notifications: %w", err)
	}
	return out, nil
}

// MarkNotificationSending records that an attempt is in flight. A crash leaves
// this state behind; RequeueStaleNotificationDeliveries resets it on startup.
func (d *DB) MarkNotificationSending(ctx context.Context, deliveryID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := formatNotificationTime(time.Now().UTC())
	_, err := d.sqlDB.ExecContext(ctx, `
		UPDATE notification_deliveries
		SET status = ?, updated_at = ?
		WHERE id = ?`,
		models.NotificationDeliverySending, now, deliveryID,
	)
	if err != nil {
		return fmt.Errorf("mark notification sending: %w", err)
	}
	return nil
}

// MarkNotificationSent records a Gotify endpoint acceptance. It is not proof of
// mobile receipt.
func (d *DB) MarkNotificationSent(ctx context.Context, deliveryID int64, attempts, httpStatus int) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := time.Now().UTC()
	res, err := d.sqlDB.ExecContext(ctx, `
		UPDATE notification_deliveries
		SET status = ?, attempts = ?, last_error = '', last_http_status = ?,
		    delivered_at = ?, updated_at = ?
		WHERE id = ?`,
		models.NotificationDeliverySent, attempts, httpStatus,
		formatNotificationTime(now), formatNotificationTime(now), deliveryID,
	)
	if err != nil {
		return fmt.Errorf("mark notification sent: %w", err)
	}
	return requireOneDelivery(res)
}

// MarkNotificationRetry records a retryable outcome. uncertain=true means the
// endpoint did not answer (timeout, connection reset, redirect refusal), which is
// different from Gotify explicitly rate-limiting or failing.
func (d *DB) MarkNotificationRetry(ctx context.Context, deliveryID int64, attempts, maxAttempts int, next time.Time, status, reason string, httpStatus int) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := formatNotificationTime(time.Now().UTC())
	nextText := formatNotificationTime(next)
	res, err := d.sqlDB.ExecContext(ctx, `
		UPDATE notification_deliveries
		SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?,
		    last_http_status = ?, updated_at = ?
		WHERE id = ?`,
		status, attempts, nextText, reason, httpStatus, now, deliveryID,
	)
	if err != nil {
		return fmt.Errorf("mark notification retry: %w", err)
	}
	return requireOneDelivery(res)
}

// RequeueStaleNotificationDeliveries returns crashed in-flight attempts to the
// queue. A restart must not lose an event or claim it was delivered.
func (d *DB) RequeueStaleNotificationDeliveries(ctx context.Context) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := formatNotificationTime(time.Now().UTC())
	_, err := d.sqlDB.ExecContext(ctx, `
		UPDATE notification_deliveries
		SET status = ?, updated_at = ?
		WHERE status = ?`,
		models.NotificationDeliveryPending, now, models.NotificationDeliverySending,
	)
	if err != nil {
		return fmt.Errorf("requeue stale notification deliveries: %w", err)
	}
	return nil
}

// GetNotificationDeliveryByEventID returns one delivery's current outcome.
func (d *DB) GetNotificationDeliveryByEventID(ctx context.Context, eventID string) (models.NotificationDelivery, error) {
	var delivery models.NotificationDelivery
	var next, created, updated, delivered sql.NullString
	err := d.sqlDB.QueryRowContext(ctx, `
		SELECT id, event_id, status, attempts, max_attempts, next_attempt_at,
		       last_error, last_http_status, force, created_at, updated_at, delivered_at
		FROM notification_deliveries WHERE event_id = ?`, eventID,
	).Scan(
		&delivery.ID, &delivery.EventID, &delivery.Status, &delivery.Attempts,
		&delivery.MaxAttempts, &next, &delivery.LastError, &delivery.LastHTTPStatus,
		&delivery.Force, &created, &updated, &delivered,
	)
	if err != nil {
		return delivery, err
	}
	delivery.NextAttemptAt = parseNotificationTime(next.String)
	delivery.CreatedAt = parseNotificationTime(created.String)
	delivery.UpdatedAt = parseNotificationTime(updated.String)
	if delivered.Valid && delivered.String != "" {
		t := parseNotificationTime(delivered.String)
		delivery.DeliveredAt = &t
	}
	return delivery, nil
}

// ListNotificationHistory returns the newest events with their delivery
// outcome. limit is clamped to a bounded page.
func (d *DB) ListNotificationHistory(ctx context.Context, limit int) ([]models.NotificationHistoryItem, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	rows, err := d.sqlDB.QueryContext(ctx, `
		SELECT e.id, e.event_key, e.incident_id, e.category, e.severity,
		       e.event_type, e.entity_type, e.entity_id, e.transition,
		       e.summary, e.detail, e.evidence, e.recovery, e.occurred_at,
		       d.id, d.status, d.attempts, d.max_attempts, d.next_attempt_at,
		       d.last_error, d.last_http_status, d.force, d.created_at,
		       d.updated_at, d.delivered_at
		FROM notification_events e
		JOIN notification_deliveries d ON d.event_id = e.id
		ORDER BY e.occurred_at DESC, e.id DESC
		LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query notification history: %w", err)
	}
	defer rows.Close()

	var out []models.NotificationHistoryItem
	for rows.Next() {
		var item models.NotificationHistoryItem
		var recovery, force int
		var occurred, next, created, updated string
		var delivered sql.NullString
		if err := rows.Scan(
			&item.Event.ID, &item.Event.EventKey, &item.Event.IncidentID,
			&item.Event.Category, &item.Event.Severity, &item.Event.Type,
			&item.Event.EntityType, &item.Event.EntityID, &item.Event.Transition,
			&item.Event.Summary, &item.Event.Detail, &item.Event.Evidence,
			&recovery, &occurred,
			&item.Delivery.ID, &item.Delivery.Status, &item.Delivery.Attempts,
			&item.Delivery.MaxAttempts, &next, &item.Delivery.LastError,
			&item.Delivery.LastHTTPStatus, &force, &created, &updated, &delivered,
		); err != nil {
			return nil, fmt.Errorf("scan notification history: %w", err)
		}
		item.Event.Recovery = recovery == 1
		item.Event.OccurredAt = parseNotificationTime(occurred)
		item.Delivery.EventID = item.Event.ID
		item.Delivery.NextAttemptAt = parseNotificationTime(next)
		item.Delivery.CreatedAt = parseNotificationTime(created)
		item.Delivery.UpdatedAt = parseNotificationTime(updated)
		item.Delivery.Force = force == 1
		if delivered.Valid && delivered.String != "" {
			t := parseNotificationTime(delivered.String)
			item.Delivery.DeliveredAt = &t
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification history: %w", err)
	}
	return out, nil
}

// NotificationTransition is one producer state change that must commit together
// with its event. ExpectedGeneration is the generation the caller observed before
// building the event key; a mismatch means another writer already advanced the
// state, so this transition is stale and must be retried on the next poll.
type NotificationTransition struct {
	Producer           string
	EntityKey          string
	PreviousState      string
	ExpectedGeneration int64
	State              string
}

// ErrNotificationTransitionStale means the producer state changed after the
// caller read it. Nothing was written: the caller retries from a fresh read.
var ErrNotificationTransitionStale = errors.New("notification producer transition is stale")

// ReadNotificationProducerState returns the durable observation state and its
// transition generation. found=false means no baseline has ever been recorded.
func (d *DB) ReadNotificationProducerState(ctx context.Context, producer, entityKey string) (state string, generation int64, found bool, err error) {
	err = d.sqlDB.QueryRowContext(ctx, `
		SELECT state, generation FROM notification_producer_state
		WHERE producer = ? AND entity_key = ?`, producer, entityKey,
	).Scan(&state, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("read notification producer state: %w", err)
	}
	return state, generation, true, nil
}

// CommitNotificationTransition atomically advances every producer transition and
// inserts the event plus delivery. A failed event insert rolls the state update
// back, so the next observation retries the same transition instead of losing it.
func (d *DB) CommitNotificationTransition(ctx context.Context, transitions []NotificationTransition, req NotificationEnqueue) (bool, error) {
	if len(transitions) == 0 {
		return false, errors.New("notification transition requires at least one state change")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := time.Now().UTC()
	event := req.Event
	event.Normalize(now)

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin notification transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, transition := range transitions {
		if err := applyNotificationTransition(ctx, tx, transition, now); err != nil {
			return false, err
		}
	}
	inserted, err := insertTransitionEvent(ctx, tx, req, event, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit notification transition: %w", err)
	}
	return inserted, nil
}

func insertTransitionEvent(ctx context.Context, tx *sql.Tx, req NotificationEnqueue, event models.NotificationEvent, now time.Time) (bool, error) {
	inserted, err := insertNotificationEventRow(ctx, tx, event, now)
	if err != nil || !inserted {
		return inserted, err
	}
	status, reason, err := notificationDeliveryDecision(ctx, tx, req, event)
	if err != nil {
		return false, err
	}
	if err := insertNotificationDeliveryRow(ctx, tx, req, event.ID, status, reason, now); err != nil {
		return false, err
	}
	return true, nil
}

func applyNotificationTransition(ctx context.Context, tx *sql.Tx, transition NotificationTransition, now time.Time) error {
	if transition.PreviousState == "" {
		return insertNotificationProducerState(ctx, tx, transition, now)
	}
	return advanceNotificationProducerState(ctx, tx, transition, now)
}

func insertNotificationProducerState(ctx context.Context, tx *sql.Tx, transition NotificationTransition, now time.Time) error {
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO notification_producer_state
			(producer, entity_key, state, generation, updated_at)
		VALUES (?, ?, ?, 1, ?)`,
		transition.Producer, transition.EntityKey, transition.State, formatNotificationTime(now),
	)
	if err != nil {
		return fmt.Errorf("insert notification producer state: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count notification producer state insert: %w", err)
	}
	if rows != 1 {
		return ErrNotificationTransitionStale
	}
	return nil
}

func advanceNotificationProducerState(ctx context.Context, tx *sql.Tx, transition NotificationTransition, now time.Time) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE notification_producer_state
		SET state = ?, generation = generation + 1, updated_at = ?
		WHERE producer = ? AND entity_key = ? AND state = ? AND generation = ?`,
		transition.State, formatNotificationTime(now), transition.Producer, transition.EntityKey,
		transition.PreviousState, transition.ExpectedGeneration,
	)
	if err != nil {
		return fmt.Errorf("advance notification producer state: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count notification producer state update: %w", err)
	}
	if rows != 1 {
		return ErrNotificationTransitionStale
	}
	return nil
}

// AdvanceNotificationTransitions applies multiple producer state changes in one
// transaction without creating an event. It is the baseline/intermediate path.
func (d *DB) AdvanceNotificationTransitions(ctx context.Context, transitions []NotificationTransition) error {
	if len(transitions) == 0 {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	now := time.Now().UTC()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin notification state advance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, transition := range transitions {
		if err := applyNotificationTransition(ctx, tx, transition, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit notification state advance: %w", err)
	}
	return nil
}

// AdvanceNotificationProducerState records the latest observed state for one
// producer entity and reports the previous state. It is used for a baseline or a
// non-notifiable state; notifiable changes use CommitNotificationTransition so
// the state cannot advance without its event. The first observation returns
// previous="" changed=true: it establishes a baseline and must not be announced
// as a transition, because there is no earlier authoritative state to compare.
func (d *DB) AdvanceNotificationProducerState(ctx context.Context, producer, entityKey, state string) (previous string, changed bool, err error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("begin producer state advance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRowContext(ctx,
		`SELECT state FROM notification_producer_state WHERE producer = ? AND entity_key = ?`,
		producer, entityKey,
	).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", false, fmt.Errorf("read producer state: %w", err)
	}
	if err == nil && previous == state {
		return previous, false, nil
	}

	now := formatNotificationTime(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO notification_producer_state (producer, entity_key, state, generation, updated_at)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(producer, entity_key) DO UPDATE
		SET state = excluded.state, generation = notification_producer_state.generation + 1, updated_at = excluded.updated_at`,
		producer, entityKey, state, now,
	); err != nil {
		return "", false, fmt.Errorf("write producer state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("commit producer state: %w", err)
	}
	return previous, true, nil
}

// GetActiveProtocols returns the protocols with at least one configured client
// connection. The aggregate no-eligible-backend alert uses this so an unused
// protocol cannot page an administrator.
func (d *DB) GetActiveProtocols(ctx context.Context) ([]string, error) {
	rows, err := d.sqlDB.QueryContext(ctx, `SELECT DISTINCT protocol FROM user_connections WHERE protocol IS NOT NULL AND protocol <> ''`)
	if err != nil {
		return nil, fmt.Errorf("query active protocols: %w", err)
	}
	defer rows.Close()
	var protocols []string
	for rows.Next() {
		var protocol string
		if err := rows.Scan(&protocol); err != nil {
			return nil, err
		}
		protocols = append(protocols, protocol)
	}
	return protocols, rows.Err()
}

func formatNotificationTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseNotificationTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func requireOneDelivery(res sql.Result) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count updated notification delivery: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("notification delivery update affected %d rows", rows)
	}
	return nil
}
