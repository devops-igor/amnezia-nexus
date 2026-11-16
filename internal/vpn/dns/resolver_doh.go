package gatewaydns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file implements DNS over HTTPS (RFC 8484) for one configured upstream
// entry. Like DoT it is a place where a query leaves the resolver encrypted, and
// it keeps the same contract.
//
// Properties the design keeps:
//   - One HTTP/2 POST over one verified TLS connection. There is no plaintext
//     attempt of any kind: the URL scheme is always https, the HTTP transport has
//     no proxy and its plaintext dial hook always fails, and the only connection
//     it can use is the one dialTLS verified.
//   - The TLS handshake is the DoT handshake (dialTLS): same system trust store,
//     same name verification, same SPKI pin check. A peer that does not negotiate
//     HTTP/2 is refused rather than spoken to in HTTP/1.1.
//   - A redirect is never followed. Following one would let the server steer the
//     query to a host the operator never configured, so a 3xx is a failure with
//     its own cause.
//   - The whole exchange, including reading the body, shares the resolver's
//     per-attempt budget. The body is capped at the largest DNS message.
//
// The method is POST rather than GET. The query travels in the body instead of
// the URL, so it does not appear in server or intermediary access logs, there is
// no URL length limit to hit and no base64url step to get wrong. GET exists for
// HTTP cacheability, which a resolver that already caches evidence does not need.

const (
	// dohPath is the well-known RFC 8484 request path. It is fixed: an entry is an
	// address, a port and a transport, so there is no configurable path or scheme.
	dohPath = "/dns-query"
	// dohMediaType is the request and response content type.
	dohMediaType = "application/dns-message"
	// maxDoHResponseBytes bounds the response body at the largest DNS message,
	// 65535 bytes. A larger body cannot be a valid answer, so it is a failure and
	// never a truncated answer.
	maxDoHResponseBytes = 65535
	// maxDoHHeaderBytes bounds the response header block. A DoH answer needs a
	// handful of short headers, so 16 KiB is generous and still stops a peer that
	// streams headers forever from consuming memory inside the attempt budget.
	maxDoHHeaderBytes = 16 << 10
)

// errDoHPlaintextForbidden is returned by the HTTP transport's plaintext dial
// hook. With an https URL the hook is never reached; it exists so that a future
// change which produces a non-https request fails closed instead of connecting.
var errDoHPlaintextForbidden = errors.New("DNS over HTTPS never uses a plaintext connection")

// dohURL is the request URL for an entry: always https, the entry's own name and
// port, and the fixed well-known path.
func dohURL(upstream policy.Upstream) string {
	host := net.JoinHostPort(dotServerName(upstream), strconv.Itoa(upstream.EffectivePort()))
	return "https://" + host + dohPath
}

// exchangeDoH performs one DNS-over-HTTPS exchange inside the attempt budget.
func (r *UpstreamResolver) exchangeDoH(ctx context.Context, req *mdns.Msg, upstream policy.Upstream) (*mdns.Msg, error) {
	budget := r.attemptBudget(ctx)
	if budget <= 0 {
		return nil, context.DeadlineExceeded
	}
	attemptCtx, cancelAttempt := context.WithTimeout(ctx, budget)
	defer cancelAttempt()

	pin, err := upstream.SPKIPinDigest()
	if err != nil {
		return nil, &dotFailure{kind: FailureCertificate, err: fmt.Errorf("upstream %s: unusable SPKI pin: %w", upstream.String(), err)}
	}

	// RFC 8484 section 4.1: the DNS ID is 0, because HTTP already pairs the
	// response with the request.
	outReq := req.Copy()
	outReq.Id = 0
	ensureEDNS0(outReq, safeEDNS0Size)
	wire, err := outReq.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS over HTTPS query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, dohURL(upstream), bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("build DNS over HTTPS request: %w", err)
	}
	httpReq.Header.Set("Content-Type", dohMediaType)
	httpReq.Header.Set("Accept", dohMediaType)

	transport := r.dohTransport(attemptCtx, upstream, pin)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// A redirect is returned to us as a response and classified, never chased.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, classifyDoHError(attemptCtx, err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	return readDoHResponse(attemptCtx, httpResp)
}

// dohTransport builds the HTTP transport for one attempt. It is pinned rather
// than derived from http.DefaultTransport so that no environment setting can
// reach it: Proxy is nil, which means no proxy is consulted whatever
// HTTP_PROXY, HTTPS_PROXY or NO_PROXY say, and every TLS connection comes from
// dialTLS. Keep-alives are off because the transport lives for one attempt, the
// same one-connection-per-exchange lifetime the DoT path has.
func (r *UpstreamResolver) dohTransport(attemptCtx context.Context, upstream policy.Upstream, pin []byte) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errDoHPlaintextForbidden
		},
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return r.dialDoH(attemptCtx, upstream, pin)
		},
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxDoHHeaderBytes,
	}
}

// dialDoH opens the verified HTTP/2 connection inside the attempt context. The
// address and context the HTTP transport passes are ignored: the entry is the
// only authority for where to connect, and the attempt context is the only
// deadline, so the handshake cannot outlive the attempt budget.
func (r *UpstreamResolver) dialDoH(attemptCtx context.Context, upstream policy.Upstream, pin []byte) (net.Conn, error) {
	conn, state, err := r.dialTLS(attemptCtx, upstream, []string{"h2"})
	if err != nil {
		return nil, classifyDoTFailure(attemptCtx, err)
	}
	if state.NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, &dotFailure{kind: FailureTLSHandshake, err: fmt.Errorf("DNS over HTTPS peer negotiated %q instead of h2", state.NegotiatedProtocol)}
	}
	if len(pin) > 0 {
		if err := verifySPKIPin(state, pin); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	// The connection lives exactly as long as the attempt, so a canceled or
	// finished attempt closes it and no goroutine or socket outlives the exchange.
	context.AfterFunc(attemptCtx, func() { _ = conn.Close() })
	return conn, nil
}

// classifyDoHError keeps a dial failure's own kind and otherwise reports an
// exhausted attempt budget as a timeout, for the same reason attemptError does.
func classifyDoHError(attemptCtx context.Context, err error) error {
	var failure *dotFailure
	if errors.As(err, &failure) {
		return err
	}
	return attemptError(attemptCtx, err)
}

// readDoHResponse turns the HTTP response into a DNS message or a classified
// failure. The order is deliberate: the status and content type are judged
// before the body is touched, and the body is bounded before it is parsed.
func readDoHResponse(attemptCtx context.Context, resp *http.Response) (*mdns.Msg, error) {
	if err := checkDoHResponseHeader(resp); err != nil {
		return nil, err
	}
	body, err := readDoHBody(attemptCtx, resp)
	if err != nil {
		return nil, err
	}
	msg := new(mdns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, &dotFailure{kind: FailureInvalidResponse, err: fmt.Errorf("DNS over HTTPS body is not a DNS message: %w", err)}
	}
	return msg, nil
}

// checkDoHResponseHeader classifies the status line and content type. A 3xx is
// reported on its own because it is never followed.
func checkDoHResponseHeader(resp *http.Response) error {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &dotFailure{kind: FailureRedirect, err: fmt.Errorf("DNS over HTTPS peer answered HTTP %d; redirects are never followed", resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &dotFailure{kind: FailureHTTPStatus, err: fmt.Errorf("DNS over HTTPS peer answered HTTP %d", resp.StatusCode)}
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != dohMediaType {
		return &dotFailure{kind: FailureContentType, err: fmt.Errorf("DNS over HTTPS response is not %s", dohMediaType)}
	}
	return nil
}

// readDoHBody reads the body within the size bound. It reads one byte more than
// the cap so an oversized body is detected instead of being cut short into
// something that might still parse.
func readDoHBody(attemptCtx context.Context, resp *http.Response) ([]byte, error) {
	if resp.ContentLength > maxDoHResponseBytes {
		return nil, errDoHTooLarge()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponseBytes+1))
	if err != nil {
		return nil, classifyDoHError(attemptCtx, err)
	}
	if len(body) > maxDoHResponseBytes {
		return nil, errDoHTooLarge()
	}
	return body, nil
}

func errDoHTooLarge() error {
	return &dotFailure{kind: FailureResponseTooLarge, err: fmt.Errorf("DNS over HTTPS response exceeds %d bytes", maxDoHResponseBytes)}
}
