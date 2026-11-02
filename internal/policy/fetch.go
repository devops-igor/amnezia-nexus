package policy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Default limits for hardened fetches.
const (
	DefaultMaxSourceBytes = 64 * 1024 * 1024 // 64 MiB
	DefaultMaxLineBytes   = 4096             // 4 KiB
	DefaultFetchTimeout   = 5 * time.Minute
)

// FetchLimits bounds resource consumption during HTTP list fetching.
type FetchLimits struct {
	MaxSourceBytes int64
	MaxLineBytes   int
	Timeout        time.Duration
}

// DefaultFetchLimits returns the production recommended bounds.
func DefaultFetchLimits() FetchLimits {
	return FetchLimits{
		MaxSourceBytes: DefaultMaxSourceBytes,
		MaxLineBytes:   DefaultMaxLineBytes,
		Timeout:        DefaultFetchTimeout,
	}
}

// FetchResult contains the downloaded rule content and caching metadata.
type FetchResult struct {
	StatusCode   int
	NotModified  bool
	ETag         string
	LastModified string
	Body         []byte
}

// ValidateFetchURL validates an external URL against strict SSRF rules.
// Only HTTPS on port 443 with a canonical hostname or approved public IPv4 is permitted.
func ValidateFetchURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "https" {
		return nil, errors.New("only https scheme is permitted")
	}
	if u.Opaque != "" {
		return nil, errors.New("opaque URLs are not permitted")
	}
	if u.User != nil {
		return nil, errors.New("userinfo in URL is not permitted")
	}
	if u.Fragment != "" {
		return nil, errors.New("fragments are not permitted in list URLs")
	}

	port := u.Port()
	if port != "" && port != "443" {
		return nil, fmt.Errorf("nonstandard port %q rejected; only port 443 is permitted", port)
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("empty host in URL")
	}
	if strings.Contains(host, ":") || strings.HasPrefix(host, "[") {
		return nil, errors.New("IPv6 host is not permitted")
	}

	// If host is an IPv4 literal, validate immediately
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if err := ValidateFetchIP(addr); err != nil {
			return nil, fmt.Errorf("host IP %s rejected: %w", host, err)
		}
	} else {
		canon, normErr := NormalizeDomain(host)
		if normErr != nil {
			return nil, fmt.Errorf("invalid host domain %q: %w", host, normErr)
		}
		if !strings.Contains(canon, ".") {
			return nil, fmt.Errorf("single-label hostname %q rejected", host)
		}
	}

	return u, nil
}

// Fetcher performs hardened HTTPS fetches of policy rule lists.
type Fetcher struct {
	limits    FetchLimits
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)
	dialTCP   func(ctx context.Context, network, addr string) (net.Conn, error)
	tlsConfig *tls.Config
}

// NewFetcher constructs a Fetcher with the given limits.
func NewFetcher(limits FetchLimits) *Fetcher {
	if limits.MaxSourceBytes <= 0 {
		limits.MaxSourceBytes = DefaultMaxSourceBytes
	}
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = DefaultMaxLineBytes
	}
	if limits.Timeout <= 0 {
		limits.Timeout = DefaultFetchTimeout
	}
	return &Fetcher{
		limits: limits,
	}
}

func (f *Fetcher) resolveIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}

	lookup := f.lookupIP
	if lookup == nil {
		lookup = func(c context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(c, "ip4", h)
		}
	}
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dnsCancel()
	res, dnsErr := lookup(dnsCtx, host)
	if dnsErr != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, dnsErr)
	}
	return res, nil
}

func (f *Fetcher) safeDial(dialCtx context.Context, addr string) (net.Conn, error) {
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, splitErr
	}
	if port != "443" {
		return nil, errors.New("forbidden destination port")
	}

	ips, err := f.resolveIPv4(dialCtx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses resolved for %s", host)
	}

	// Enforce SSRF defense across ALL candidate IPs. If any returned candidate
	// belongs to a private, loopback, or metadata range, reject immediately.
	for _, ip := range ips {
		if err := ValidateFetchIP(ip); err != nil {
			return nil, fmt.Errorf("SSRF defense blocked resolved IP %s: %w", ip, err)
		}
	}

	dialFunc := f.dialTCP
	if dialFunc == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		dialFunc = dialer.DialContext
	}

	// Dial approved literal IP directly to prevent DNS rebinding
	var lastDialErr error
	for _, ip := range ips {
		literalTarget := net.JoinHostPort(ip.String(), port)
		conn, dErr := dialFunc(dialCtx, "tcp4", literalTarget)
		if dErr == nil {
			return conn, nil
		}
		lastDialErr = dErr
	}
	return nil, fmt.Errorf("failed to dial resolved IP candidates: %w", lastDialErr)
}

func (f *Fetcher) readResponseBody(resp *http.Response) ([]byte, error) {
	enc := resp.Header.Get("Content-Encoding")
	if enc != "" && enc != "identity" {
		return nil, fmt.Errorf("unsupported content encoding %q; identity required", enc)
	}

	if resp.ContentLength > f.limits.MaxSourceBytes {
		return nil, fmt.Errorf("content-length %d exceeds limit of %d bytes", resp.ContentLength, f.limits.MaxSourceBytes)
	}

	// Read body with limit + 1 to detect truncation
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, f.limits.MaxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %w", err)
	}
	if int64(len(bodyBytes)) > f.limits.MaxSourceBytes {
		return nil, fmt.Errorf("response body exceeded limit of %d bytes", f.limits.MaxSourceBytes)
	}

	// Reject obvious HTML, XML, or JSON error/challenge documents
	trimmed := bytes.TrimLeft(bodyBytes, " \t\r\n")
	sampleLen := 128
	if len(trimmed) < sampleLen {
		sampleLen = len(trimmed)
	}
	sample := strings.ToLower(string(trimmed[:sampleLen]))
	if strings.HasPrefix(sample, "<!doctype html") ||
		strings.HasPrefix(sample, "<html") ||
		strings.HasPrefix(sample, "<?xml") ||
		strings.HasPrefix(sample, "{") ||
		strings.HasPrefix(sample, "[") {
		return nil, errors.New("invalid payload format: unexpected HTML, XML, or JSON document")
	}

	return bodyBytes, nil
}

// Fetch downloads list data from reqURL using hardened SSRF-resistant transport.
// Conditional validators (ifNoneMatch, ifModifiedSince) can be provided for HTTP 304 reuse.
func (f *Fetcher) Fetch(ctx context.Context, reqURL string, ifNoneMatch, ifModifiedSince string) (*FetchResult, error) {
	parsedURL, err := ValidateFetchURL(reqURL)
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}

	fetchCtx, fetchCancel := context.WithTimeout(ctx, f.limits.Timeout)
	defer fetchCancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	if ifModifiedSince != "" {
		req.Header.Set("If-Modified-Since", ifModifiedSince)
	}

	tlsCfg := f.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	tr := &http.Transport{
		Proxy:                  nil, // Never inherit HTTP(S)_PROXY
		DialContext:            func(c context.Context, network, addr string) (net.Conn, error) { return f.safeDial(c, addr) },
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(redirectReq *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects (max 5)")
			}
			if _, vErr := ValidateFetchURL(redirectReq.URL.String()); vErr != nil {
				return fmt.Errorf("redirect target rejected: %w", vErr)
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &FetchResult{
			StatusCode:   http.StatusNotModified,
			NotModified:  true,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, resp.Status)
	}

	bodyBytes, err := f.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	return &FetchResult{
		StatusCode:   http.StatusOK,
		NotModified:  false,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		Body:         bodyBytes,
	}, nil
}
