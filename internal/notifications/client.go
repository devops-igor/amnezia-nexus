package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	gotifyRequestTimeout = 10 * time.Second
	gotifyMaxBodyBytes   = 64 << 10
	gotifyMaxMessageLen  = 4000
)

// HTTPStatusError is a Gotify response with a non-2xx status. It is distinct
// from a transport failure: Gotify answered, so the delivery outcome is known.
type HTTPStatusError struct {
	Status int
	Body   string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("gotify returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("gotify returned HTTP %d: %s", e.Status, e.Body)
}

// Message is the provider-neutral payload handed to an external channel.
type Message struct {
	Title    string
	Body     string
	Priority int
}

// Client sends notifications to a Gotify endpoint over a bounded, verified TLS
// connection. Redirects are refused so a hostile or misconfigured destination
// cannot bounce the request to another host after validation.
type Client struct {
	httpClient *http.Client
}

// ClientOption configures the Gotify client.
type ClientOption func(*Client)

// WithHTTPClient injects a client, used by tests that need a controlled
// receiver certificate or transport.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// NewClient builds the production Gotify client. The custom dialer re-checks
// every resolved address so a hostname cannot resolve to link-local metadata
// after the URL itself passed validation.
func NewClient(opts ...ClientOption) *Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           safeDialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	client := &Client{httpClient: &http.Client{
		Transport: transport,
		Timeout:   gotifyRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("gotify redirects are not allowed")
		},
	}}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

// ValidateEndpoint validates an administrator-supplied Gotify base URL.
//
// HTTPS is required, except for a loopback receiver used by local testing. URL
// credentials, fragments and query strings are refused so a token cannot be
// smuggled into the destination or a log line. Literal link-local, multicast
// and unspecified addresses are refused; hostname resolution is re-checked at
// dial time.
func ValidateEndpoint(raw string) (*url.URL, error) {
	parsed, err := parseEndpointURL(raw)
	if err != nil {
		return nil, err
	}
	if err := validateEndpointAuthority(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func parseEndpointURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("gotify URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid gotify URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("gotify URL must use https")
	}
	if parsed.User != nil {
		return nil, errors.New("gotify URL must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("gotify URL must not contain a query or fragment")
	}
	return parsed, nil
}

func validateEndpointAuthority(parsed *url.URL) error {
	host := parsed.Hostname()
	if parsed.Host == "" || host == "" {
		return errors.New("gotify URL must include a host")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(host) {
		return errors.New("gotify URL must use https unless it is a loopback test receiver")
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkDialIP(ip, host)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkDialIP(ip net.IP, host string) error {
	if ip == nil {
		return errors.New("gotify host did not resolve to an address")
	}
	if ip.IsUnspecified() {
		return errors.New("gotify destination must not be an unspecified address")
	}
	if ip.IsMulticast() {
		return errors.New("gotify destination must not be a multicast address")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return errors.New("gotify destination must not be a link-local address")
	}
	if ip.IsLoopback() && !isLoopbackHost(host) {
		return errors.New("gotify hostname resolved to a loopback address")
	}
	return nil
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid gotify destination %q: %w", address, err)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve gotify host: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("gotify host resolved to no addresses")
	}
	var lastErr error
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, candidate := range ips {
		if err := checkDialIP(candidate.IP, host); err != nil {
			lastErr = err
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable gotify address")
	}
	return nil, lastErr
}

// TestConnection verifies the configured endpoint and application token without
// sending an event. Gotify's /version endpoint is authenticated.
func (c *Client) TestConnection(ctx context.Context, baseURL, token string) error {
	base, err := ValidateEndpoint(baseURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("gotify application token is required")
	}
	endpoint := buildEndpoint(base, "/version")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build gotify version request: %w", err)
	}
	req.Header.Set("X-Gotify-Key", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gotify connection failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, gotifyMaxBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPStatusError{Status: resp.StatusCode, Body: summarizeBody(body)}
	}
	return nil
}

// Send posts one message to Gotify. It returns the HTTP status on success and a
// typed error otherwise. The token is sent as a header, never in the URL.
func (c *Client) Send(ctx context.Context, baseURL, token string, msg Message) (int, error) {
	base, err := ValidateEndpoint(baseURL)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(token) == "" {
		return 0, errors.New("gotify application token is required")
	}
	payload := map[string]any{
		"title":    sanitizeMessage(msg.Title, token),
		"message":  truncateMessage(sanitizeMessage(msg.Body, token)),
		"priority": msg.Priority,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("encode gotify message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, buildEndpoint(base, "/message"), bytes.NewReader(encoded))
	if err != nil {
		return 0, fmt.Errorf("build gotify message request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, gotifyMaxBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, &HTTPStatusError{Status: resp.StatusCode, Body: summarizeBody(body)}
	}
	return resp.StatusCode, nil
}

func buildEndpoint(base *url.URL, suffix string) string {
	copied := *base
	copied.Path = strings.TrimRight(copied.Path, "/") + suffix
	return copied.String()
}

func sanitizeMessage(text, token string) string {
	if token != "" {
		text = strings.ReplaceAll(text, token, "[redacted]")
	}
	return strings.TrimSpace(text)
}

func truncateMessage(text string) string {
	if len(text) <= gotifyMaxMessageLen {
		return text
	}
	return text[:gotifyMaxMessageLen] + "…"
}

func summarizeBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	return text
}

// Priority maps severity to Gotify's priority scale.
func Priority(severity models.NotificationSeverity) int {
	switch severity {
	case models.NotificationSeverityCritical:
		return 8
	case models.NotificationSeverityWarning:
		return 5
	default:
		return 2
	}
}

// IsPermanent reports whether an HTTP error should not be retried.
func IsPermanent(err error) bool {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.Status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	if statusErr.Status >= 400 && statusErr.Status < 500 {
		return true
	}
	return false
}

// StatusCode extracts an HTTP status from an error, or 0 for a transport error.
func StatusCode(err error) int {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status
	}
	return 0
}

// FormatAttemptReason renders a bounded, token-free reason for history.
func FormatAttemptReason(err error) string {
	if err == nil {
		return ""
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return "gotify HTTP " + strconv.Itoa(statusErr.Status)
	}
	// Transport errors can name the destination host. History is visible to
	// administrators, but the recorded reason does not need private
	// infrastructure detail to be truthful.
	return "gotify connection failed (no response)"
}
