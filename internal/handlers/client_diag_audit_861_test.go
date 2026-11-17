package handlers

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Access-audit contract for the per-client diagnosis read (issue #861).
//
// One accepted read writes exactly one access event naming the actor and the selected
// session. The event must not carry browsing metadata: no DNS name, answer, address, port,
// payload or request/response body. Refusals that never read retained evidence write
// nothing, and requests the middleware stops never reach this handler.

// auditCapture collects the audit records this package writes through slog.
type auditCapture struct {
	mu      sync.Mutex
	records []map[string]any
}

func (c *auditCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *auditCapture) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]any{"msg": rec.Message}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	c.mu.Lock()
	c.records = append(c.records, attrs)
	c.mu.Unlock()
	return nil
}

func (c *auditCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *auditCapture) WithGroup(string) slog.Handler      { return c }

func (c *auditCapture) diagnosisEvents() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, rec := range c.records {
		if event, _ := rec["event"].(string); event == clientDiagnosisAuditEvent {
			out = append(out, rec)
		}
	}
	return out
}

func (c *auditCapture) all() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]map[string]any, len(c.records))
	copy(out, c.records)
	return out
}

// captureAudit installs the capture as the default slog handler for one test and restores
// the previous default afterwards. The default logger is process-wide by design, so this
// test does not run in parallel with others in the package.
func captureAudit(t *testing.T) *auditCapture {
	t.Helper()
	cap := &auditCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(cap))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return cap
}

// postingDiagnosis runs the handler with the given body and returns the recorder.
func postingDiagnosis(h *Handlers, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/policy/client-diagnosis", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClientDiagnosisHandler(w, req)
	return w
}

// TestClientDiagnosisReadWritesOneAccessEvent proves the accepted read is audited once,
// with the actor and the selected session, and with no browsing metadata.
func TestClientDiagnosisReadWritesOneAccessEvent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	capture := captureAudit(t)

	// The selected identity is allowed in the audit line; a browsing sentinel supplied in
	// the request is not, and must not reach the log through any field.
	const sessionSentinel = "sess-audit-sentinel"
	const browsingSentinel = "browsing-sentinel.example"
	body := `{"session_id":"` + sessionSentinel + `","destination":{"domain":"` + browsingSentinel + `"}}`

	w := postingDiagnosis(h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("accepted read = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	events := capture.diagnosisEvents()
	if len(events) != 1 {
		t.Fatalf("access events = %d, want exactly one per accepted read: %v", len(events), capture.all())
	}
	event := events[0]
	if got, _ := event["session_id"].(string); got != sessionSentinel {
		t.Errorf("session_id = %q, want the selected session", got)
	}
	if _, ok := event["actor"]; !ok {
		t.Error("the event names no actor")
	}
	if _, ok := event["selection_state"]; !ok {
		t.Error("the event states no selection verdict")
	}

	// No browsing metadata, in any form this handler could have passed.
	rendered := renderAttrs(event)
	for _, forbidden := range []string{browsingSentinel, "1.1.1.1", "443", "\"payload\""} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the access event leaks %q: %s", forbidden, rendered)
		}
	}
	// And the response body, which does carry state, is not copied into the event.
	if strings.Contains(rendered, w.Body.String()) && len(w.Body.String()) > 24 {
		t.Error("the access event contains the whole response body")
	}
}

// renderAttrs flattens an event for sentinel scanning.
func renderAttrs(event map[string]any) string {
	var b strings.Builder
	for k, v := range event {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strings.TrimSpace(strings.Join([]string{toString(v)}, " ")))
		b.WriteString(" ")
	}
	return b.String()
}

func toString(v any) string {
	if typed, ok := v.(string); ok {
		return typed
	}
	return fmt.Sprint(v)
}

// TestClientDiagnosisRefusalsWriteNoAccessEvent proves a request that read no retained
// evidence produces no event, so the log states real reads only.
func TestClientDiagnosisRefusalsWriteNoAccessEvent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	capture := captureAudit(t)

	for _, body := range []string{``, `{`, `{}`, `{"session_id":""}`} {
		w := postingDiagnosis(h, body)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusServiceUnavailable {
			t.Fatalf("refusal for %q = %d, want a client-side refusal", body, w.Code)
		}
	}
	if events := capture.diagnosisEvents(); len(events) != 0 {
		t.Fatalf("refusals wrote %d access events, want none: %v", len(events), events)
	}
}
