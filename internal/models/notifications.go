package models

import (
	"strings"
	"time"
)

// NotificationSeverity classifies how urgently an administrator should act.
type NotificationSeverity string

const (
	NotificationSeverityInfo     NotificationSeverity = "info"
	NotificationSeverityWarning  NotificationSeverity = "warning"
	NotificationSeverityCritical NotificationSeverity = "critical"
)

// Rank returns an ordered value for threshold comparisons. Unknown severities
// rank below info so a stored invalid value cannot silently promote an event.
func (s NotificationSeverity) Rank() int {
	switch s {
	case NotificationSeverityCritical:
		return 3
	case NotificationSeverityWarning:
		return 2
	case NotificationSeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether the severity is a supported value.
func (s NotificationSeverity) Valid() bool {
	return s.Rank() > 0
}

// NotificationCategory is the administrator-facing delivery grouping.
type NotificationCategory string

const (
	NotificationCategoryServerHealth     NotificationCategory = "server_health"
	NotificationCategoryBackendHealth    NotificationCategory = "backend_health"
	NotificationCategoryProvisioning     NotificationCategory = "provisioning"
	NotificationCategoryUpdates          NotificationCategory = "updates"
	NotificationCategoryFailover         NotificationCategory = "failover"
	NotificationCategoryNotificationTest NotificationCategory = "notification_test"
)

// NotificationCategories lists every configurable category in stable order.
var NotificationCategories = []NotificationCategory{
	NotificationCategoryServerHealth,
	NotificationCategoryBackendHealth,
	NotificationCategoryProvisioning,
	NotificationCategoryUpdates,
	NotificationCategoryFailover,
}

// Valid reports whether the category is configurable by an administrator.
func (c NotificationCategory) Valid() bool {
	for _, candidate := range NotificationCategories {
		if c == candidate {
			return true
		}
	}
	return false
}

// NotificationEvent is one durable fact produced by an authoritative subsystem.
//
// EventKey is the producer-owned idempotency identity. Publishing the same key
// twice records one event and one delivery, which is how repeated polls and
// restart replays avoid duplicate pushes. IncidentID groups the transitions of
// one underlying incident (server outage, order, failover) so history and
// future phases can present a coherent story.
type NotificationEvent struct {
	ID         string               `json:"id"`
	EventKey   string               `json:"event_key"`
	IncidentID string               `json:"incident_id"`
	Category   NotificationCategory `json:"category"`
	Severity   NotificationSeverity `json:"severity"`
	Type       string               `json:"type"`
	EntityType string               `json:"entity_type"`
	EntityID   string               `json:"entity_id"`
	Transition string               `json:"transition"`
	Summary    string               `json:"summary"`
	Detail     string               `json:"detail"`
	Evidence   string               `json:"evidence"`
	Recovery   bool                 `json:"recovery"`
	// Silent records an event in durable history without external delivery,
	// used for intentional administrative actions such as a setup cancellation.
	Silent     bool      `json:"silent,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Normalize fills the identities the producer may safely omit. It never invents
// an incident identity or a summary: those are the producer's facts.
func (e *NotificationEvent) Normalize(now time.Time) {
	e.ID = strings.TrimSpace(e.ID)
	e.EventKey = strings.TrimSpace(e.EventKey)
	e.IncidentID = strings.TrimSpace(e.IncidentID)
	e.Type = strings.TrimSpace(e.Type)
	e.EntityType = strings.TrimSpace(e.EntityType)
	e.EntityID = strings.TrimSpace(e.EntityID)
	e.Transition = strings.TrimSpace(e.Transition)
	e.Summary = strings.TrimSpace(e.Summary)
	e.Detail = strings.TrimSpace(e.Detail)
	e.Evidence = strings.TrimSpace(e.Evidence)
	if e.OccurredAt.IsZero() {
		e.OccurredAt = now
	}
}

// NotificationDelivery statuses. A delivery is durable independently of the
// event so a restart can resume an unfinished attempt.
const (
	NotificationDeliveryPending    = "pending"
	NotificationDeliverySending    = "sending"
	NotificationDeliverySent       = "sent"
	NotificationDeliveryFailed     = "failed"
	NotificationDeliveryUncertain  = "uncertain"
	NotificationDeliverySuppressed = "suppressed"
	NotificationDeliveryDropped    = "dropped"
)

// NotificationDelivery is the verifiable delivery state of one event. Sending
// to Gotify is not mobile receipt; "sent" means the Gotify endpoint accepted
// the message.
type NotificationDelivery struct {
	ID             int64      `json:"id"`
	EventID        string     `json:"event_id"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	MaxAttempts    int        `json:"max_attempts"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
	LastError      string     `json:"last_error,omitempty"`
	LastHTTPStatus int        `json:"last_http_status,omitempty"`
	Force          bool       `json:"force,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
}

// NotificationHistoryItem is one event joined to its delivery outcome.
type NotificationHistoryItem struct {
	Event    NotificationEvent    `json:"event"`
	Delivery NotificationDelivery `json:"delivery"`
}

// NotificationDispatch is the dispatcher's work item: the event plus its
// current delivery attempt state.
type NotificationDispatch struct {
	DeliveryID  int64
	Attempts    int
	MaxAttempts int
	Force       bool
	Event       NotificationEvent
}

// FailoverOutcome is the observed result of one failover attempt. It is emitted
// by the VPN data-plane owner after its authoritative migration attempt, never
// inferred by a second monitor.
type FailoverOutcome struct {
	SourceTunnelID int64
	SourceServerID int64
	Protocol       string
	Decision       string // success, partial, no_target
	Migrated       int
	Stranded       int
	Manual         bool
}

// NotificationSettings is the administrator-owned delivery policy. The
// application token is encrypted at rest and masked on every read.
type NotificationSettings struct {
	Enabled         bool                 `json:"enabled"`
	URL             string               `json:"url"`
	AppToken        string               `json:"app_token"`
	MinSeverity     NotificationSeverity `json:"min_severity"`
	Categories      map[string]bool      `json:"categories"`
	CooldownSeconds int                  `json:"cooldown_seconds"`
	MaxAttempts     int                  `json:"max_attempts"`
}

// DefaultNotificationSettings is the disabled-by-default policy for fresh and
// existing installations.
func DefaultNotificationSettings() NotificationSettings {
	categories := make(map[string]bool, len(NotificationCategories))
	for _, category := range NotificationCategories {
		categories[string(category)] = true
	}
	return NotificationSettings{
		Enabled:         false,
		URL:             "",
		AppToken:        "",
		MinSeverity:     NotificationSeverityInfo,
		Categories:      categories,
		CooldownSeconds: 60,
		MaxAttempts:     6,
	}
}

// Normalize applies defaults for absent fields without enabling delivery.
func (s *NotificationSettings) Normalize() {
	if !s.MinSeverity.Valid() {
		s.MinSeverity = NotificationSeverityInfo
	}
	if s.Categories == nil {
		s.Categories = make(map[string]bool, len(NotificationCategories))
	}
	for _, category := range NotificationCategories {
		if _, ok := s.Categories[string(category)]; !ok {
			s.Categories[string(category)] = true
		}
	}
	if s.CooldownSeconds < 0 {
		s.CooldownSeconds = 0
	}
	if s.CooldownSeconds > 86400 {
		s.CooldownSeconds = 86400
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 6
	}
	if s.MaxAttempts > 20 {
		s.MaxAttempts = 20
	}
	if s.CooldownSeconds == 0 {
		s.CooldownSeconds = 60
	}
}

// CategoryEnabled reports the effective delivery toggle for a category.
func (s NotificationSettings) CategoryEnabled(category NotificationCategory) bool {
	if enabled, ok := s.Categories[string(category)]; ok {
		return enabled
	}
	// Unknown categories are not deliverable by default; the caller records a
	// suppressed delivery rather than guessing.
	return false
}

// SaveNotificationSettingsRequest is the administrator write payload. An empty
// or masked app_token preserves the stored token.
type SaveNotificationSettingsRequest struct {
	Enabled         bool                 `json:"enabled"`
	URL             string               `json:"url"`
	AppToken        string               `json:"app_token"`
	MinSeverity     NotificationSeverity `json:"min_severity"`
	Categories      map[string]bool      `json:"categories"`
	CooldownSeconds int                  `json:"cooldown_seconds"`
	MaxAttempts     int                  `json:"max_attempts"`
}

// NotificationSettingsResponse is the masked administrator read payload.
type NotificationSettingsResponse struct {
	Enabled         bool                 `json:"enabled"`
	URL             string               `json:"url"`
	AppTokenSet     bool                 `json:"app_token_set"`
	MinSeverity     NotificationSeverity `json:"min_severity"`
	Categories      map[string]bool      `json:"categories"`
	CooldownSeconds int                  `json:"cooldown_seconds"`
	MaxAttempts     int                  `json:"max_attempts"`
}
