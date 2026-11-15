package gatewaydns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// FailureKind classifies why one upstream attempt produced no usable answer, so
// the policy status can distinguish a blocked or unreachable provider from
// "policy routing has produced no evidence yet".
type FailureKind string

const (
	// FailureTimeout means the attempt produced no response inside its deadline.
	FailureTimeout FailureKind = "timeout"
	// FailureNetwork means the exchange failed at the transport level: dial
	// refused, unreachable, reset, or a local I/O error.
	FailureNetwork FailureKind = "network"
	// FailureServfail means the upstream answered but with SERVFAIL.
	FailureServfail FailureKind = "servfail"
	// FailureInvalidResponse means the reply did not match the query envelope.
	FailureInvalidResponse FailureKind = "invalid_response"
	// The remaining kinds belong to the encrypted transports. They are part of
	// the status contract from the start so an operator-facing consumer never
	// has to change shape when those transports land.
	FailureTLSHandshake FailureKind = "tls_handshake"
	FailureCertificate  FailureKind = "certificate"
	FailureHTTPStatus   FailureKind = "http_status"
)

// ResolverStatus is the operator-facing view of the last upstream outcome.
//
// LastUpstream names the upstream that served the most recent accepted answer.
// LastFailure and LastFailureKind describe the most recent failed attempt and
// are cleared by a later successful exchange: a working provider is not
// reported as failing. An empty LastFailure therefore means "the last exchange
// succeeded", which is different from "no exchange has happened yet"
// (LastUpstream is then empty as well).
type ResolverStatus struct {
	LastUpstream    string
	LastFailure     string
	LastFailureKind FailureKind
}

// Resolver performs upstream DNS exchanges within strict query and attempt budgets.
type Resolver interface {
	Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

// ResolverConfig defines configuration for UpstreamResolver.
type ResolverConfig struct {
	// Upstreams is the ordered upstream list. The first entry is the primary and
	// the second is the single alternate.
	Upstreams []policy.Upstream
	// QueryTimeout bounds the whole exchange, including every retry.
	QueryTimeout time.Duration
	// AttemptTimeout bounds one upstream attempt.
	AttemptTimeout time.Duration
	// AllowLoopbackUpstream admits loopback entries, which the resolver test
	// fixtures need. The persisted configuration never allows them.
	AllowLoopbackUpstream bool
}

const (
	defaultQueryTimeout   = 4 * time.Second
	defaultAttemptTimeout = 1 * time.Second
	safeEDNS0Size         = 1232
)

var (
	// ErrNoUpstreams indicates no upstream resolvers were configured.
	ErrNoUpstreams = errors.New("no upstream resolvers configured")
	// ErrTooManyUpstreams indicates more than the configured maximum were supplied.
	ErrTooManyUpstreams = errors.New("at most 3 upstream resolvers allowed")
	// ErrInvalidUpstream indicates an upstream entry is unusable: malformed,
	// unspecified, multicast, or loopback where loopback is not allowed.
	ErrInvalidUpstream = errors.New("invalid upstream resolver address")
	// ErrUnsupportedTransport indicates an entry selects a transport this build
	// does not implement. It is never served by the plain transport, because a
	// silent downgrade would send the query in clear text.
	ErrUnsupportedTransport = errors.New("upstream transport not implemented")
	// ErrInvalidRequest indicates a nil or empty DNS request.
	ErrInvalidRequest = errors.New("invalid DNS request")
	// ErrExchangeFailed indicates all upstream attempts failed within the query budget.
	ErrExchangeFailed = errors.New("upstream DNS exchange failed")
)

// UpstreamResolver handles forwarding queries to recursive resolvers with retry and TCP fallback.
type UpstreamResolver struct {
	queryTimeout   time.Duration
	attemptTimeout time.Duration
	allowLoopback  bool

	// upstreams holds the current list for concurrent readers. A live
	// configuration change swaps it atomically, so an exchange in flight always
	// sees one coherent list.
	upstreams atomic.Pointer[[]policy.Upstream]

	statusMu sync.Mutex
	status   ResolverStatus
}

// NewUpstreamResolver validates configuration and creates an UpstreamResolver.
func NewUpstreamResolver(cfg ResolverConfig) (*UpstreamResolver, error) {
	res := &UpstreamResolver{
		allowLoopback: cfg.AllowLoopbackUpstream,
	}
	if cfg.QueryTimeout > 0 {
		res.queryTimeout = cfg.QueryTimeout
	} else {
		res.queryTimeout = defaultQueryTimeout
	}
	if cfg.AttemptTimeout > 0 {
		res.attemptTimeout = cfg.AttemptTimeout
	} else {
		res.attemptTimeout = defaultAttemptTimeout
	}
	if err := res.SetUpstreams(cfg.Upstreams); err != nil {
		return nil, err
	}
	return res, nil
}

// ValidateUpstreams reports whether a list may be installed. It is the single
// admission rule the resolver constructor, the setter and the service lifecycle
// apply, so a list accepted in one place is accepted everywhere.
func ValidateUpstreams(upstreams []policy.Upstream, allowLoopback bool) error {
	if len(upstreams) == 0 {
		return ErrNoUpstreams
	}
	if len(upstreams) > policy.MaxUpstreams {
		return ErrTooManyUpstreams
	}
	for _, upstream := range upstreams {
		if err := validateUpstreamEntry(upstream, allowLoopback); err != nil {
			return err
		}
	}
	return nil
}

// SetUpstreams replaces the upstream list. The candidate list is validated as a
// whole before it is published, so a rejected change leaves the previous
// working list in effect and never yields a resolver with no upstream.
func (r *UpstreamResolver) SetUpstreams(upstreams []policy.Upstream) error {
	if err := ValidateUpstreams(upstreams, r.allowLoopback); err != nil {
		return err
	}
	published := make([]policy.Upstream, len(upstreams))
	copy(published, upstreams)
	r.upstreams.Store(&published)
	return nil
}

// Upstreams returns the current upstream list. The slice is owned by the caller.
func (r *UpstreamResolver) Upstreams() []policy.Upstream {
	current := r.upstreams.Load()
	if current == nil {
		return nil
	}
	out := make([]policy.Upstream, len(*current))
	copy(out, *current)
	return out
}

// Status reports the last upstream outcome for the policy status surface.
func (r *UpstreamResolver) Status() ResolverStatus {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	return r.status
}

// validateUpstreamEntry re-checks one entry at the point of use. The persisted
// configuration is already validated, and this repeat is the trust-boundary
// check: a programmatic caller can never install an entry the plain transport
// would dial in clear text or cannot dial at all.
func validateUpstreamEntry(upstream policy.Upstream, allowLoopback bool) error {
	if transport := upstream.EffectiveTransport(); transport != policy.TransportPlain {
		return fmt.Errorf("%w: %s selects transport %q (plaintext is never used for it)", ErrUnsupportedTransport, upstream.String(), transport)
	}
	if err := upstream.Validate(); err != nil {
		if allowLoopback && errors.Is(err, policy.ErrUpstreamLoopback) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrInvalidUpstream, err)
	}
	return nil
}

// Exchange forwards req to configured upstreams within the query budget.
// Handles UDP exchange, retries TC=1 over TCP, and falls back to at most 1
// alternate upstream. A transport failure is returned as an error, never as a
// valid empty answer.
func (r *UpstreamResolver) Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, ErrInvalidRequest
	}
	configured := r.Upstreams()
	if len(configured) == 0 {
		return nil, ErrNoUpstreams
	}

	// Bound overall query deadline.
	queryCtx, cancelQuery := context.WithTimeout(ctx, r.queryTimeout)
	defer cancelQuery()

	// Attempt the primary plus at most 1 alternate, in the configured order.
	attempts := configured
	if len(attempts) > 2 {
		attempts = attempts[:2]
	}
	resp, err := r.runAttempts(queryCtx, ctx, req, attempts)
	if err != nil {
		return nil, err
	}
	resp.Id = req.Id
	return resp, nil
}

// runAttempts contacts the primary and, on a transport failure, SERVFAIL or an
// unusable envelope, the single alternate. A terminal answer - including
// NXDOMAIN and a SERVFAIL with no alternate left - is returned to the caller.
//
// callerCtx is the caller's own context: a cancellation that came from the
// client is not an upstream failure and must not be reported as one.
func (r *UpstreamResolver) runAttempts(queryCtx, callerCtx context.Context, req *mdns.Msg, attempts []policy.Upstream) (*mdns.Msg, error) {
	var lastErr error
	for i, upstream := range attempts {
		if queryCtx.Err() != nil {
			return nil, queryCtx.Err()
		}

		resp, err := r.attemptExchange(queryCtx, req, upstream)
		if err != nil {
			lastErr = err
			r.recordFailure(callerCtx, upstream, classifyAttemptError(err))
			continue
		}

		if kind, reason := responseEnvelopeFailure(resp, req.Question[0]); kind != "" {
			lastErr = fmt.Errorf("%w: %s from %v", ErrExchangeFailed, reason, upstream.String())
			r.recordFailure(callerCtx, upstream, kind)
			continue
		}

		// A SERVFAIL is worth one alternate; with none left it is the answer.
		if resp.Rcode == mdns.RcodeServerFailure && i < len(attempts)-1 {
			lastErr = fmt.Errorf("%w: servfail from %v", ErrExchangeFailed, upstream.String())
			r.recordFailure(callerCtx, upstream, FailureServfail)
			continue
		}

		r.recordSuccess(upstream)
		return resp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrExchangeFailed
}

// responseEnvelopeFailure classifies a reply that must not be returned to the
// client. An empty kind means the reply is usable.
func responseEnvelopeFailure(resp *mdns.Msg, expected mdns.Question) (FailureKind, string) {
	if resp == nil || !resp.Response || resp.Opcode != mdns.OpcodeQuery {
		return FailureInvalidResponse, "invalid response flags"
	}
	if len(resp.Question) == 0 ||
		!strings.EqualFold(resp.Question[0].Name, expected.Name) ||
		resp.Question[0].Qtype != expected.Qtype ||
		resp.Question[0].Qclass != expected.Qclass {
		return FailureInvalidResponse, "response question mismatch"
	}
	return "", ""
}

// recordSuccess publishes the upstream that served the accepted answer and
// clears the failure state, so a working provider is not reported as failing.
func (r *UpstreamResolver) recordSuccess(upstream policy.Upstream) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.status = ResolverStatus{LastUpstream: upstream.String()}
}

// recordFailure publishes the failed attempt. A caller-side cancellation is not
// an upstream failure and leaves the status untouched.
func (r *UpstreamResolver) recordFailure(ctx context.Context, upstream policy.Upstream, kind FailureKind) {
	if ctx.Err() != nil {
		return
	}
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.status.LastFailure = upstream.String()
	r.status.LastFailureKind = kind
}

// classifyAttemptError maps one failed attempt to the operator-facing kind.
func classifyAttemptError(err error) FailureKind {
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return FailureTimeout
	}
	return FailureNetwork
}

func (r *UpstreamResolver) attemptExchange(ctx context.Context, req *mdns.Msg, upstream policy.Upstream) (*mdns.Msg, error) {
	// The transport dispatch lives here so an entry configured for an encrypted
	// transport can never be served by the plain path, even if a future caller
	// bypasses SetUpstreams' validation.
	switch upstream.EffectiveTransport() {
	case policy.TransportPlain:
		return r.exchangePlain(ctx, req, upstream)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTransport, upstream.String())
	}
}

func (r *UpstreamResolver) exchangePlain(ctx context.Context, req *mdns.Msg, upstream policy.Upstream) (*mdns.Msg, error) {
	attemptDeadline := r.attemptTimeout
	if d, ok := ctx.Deadline(); ok {
		remaining := time.Until(d)
		if remaining < attemptDeadline {
			attemptDeadline = remaining
		}
	}
	if attemptDeadline <= 0 {
		return nil, context.DeadlineExceeded
	}

	attemptCtx, cancelAttempt := context.WithTimeout(ctx, attemptDeadline)
	defer cancelAttempt()

	outReq := req.Copy()
	outReq.Id = mdns.Id()
	ensureEDNS0(outReq, safeEDNS0Size)

	target := upstream.HostPort()
	client := &mdns.Client{Net: "udp", Timeout: attemptDeadline}

	conn, err := client.DialContext(attemptCtx, target)
	if err != nil {
		return nil, err
	}
	stopAfter := context.AfterFunc(attemptCtx, func() { _ = conn.Close() })
	resp, _, err := client.ExchangeWithConnContext(attemptCtx, outReq, conn)
	stopAfter()
	_ = conn.Close()

	if err != nil {
		return nil, attemptError(attemptCtx, err)
	}

	// If truncated (TC=1), retry over TCP to the same upstream within remaining budget.
	if resp != nil && resp.Truncated {
		return r.exchangeTCP(ctx, outReq, target)
	}

	return resp, nil
}

func (r *UpstreamResolver) exchangeTCP(ctx context.Context, outReq *mdns.Msg, target string) (*mdns.Msg, error) {
	attemptDeadline := r.attemptTimeout
	if d, ok := ctx.Deadline(); ok {
		remaining := time.Until(d)
		if remaining < attemptDeadline {
			attemptDeadline = remaining
		}
	}
	if attemptDeadline <= 0 {
		return nil, context.DeadlineExceeded
	}

	tcpCtx, cancelTCP := context.WithTimeout(ctx, attemptDeadline)
	defer cancelTCP()

	tcpClient := &mdns.Client{Net: "tcp", Timeout: attemptDeadline}
	tcpConn, err := tcpClient.DialContext(tcpCtx, target)
	if err != nil {
		return nil, err
	}
	stopAfter := context.AfterFunc(tcpCtx, func() { _ = tcpConn.Close() })
	resp, _, err := tcpClient.ExchangeWithConnContext(tcpCtx, outReq, tcpConn)
	stopAfter()
	_ = tcpConn.Close()

	if err != nil {
		return nil, attemptError(tcpCtx, err)
	}
	return resp, nil
}

// attemptError preserves the fact that an attempt ran out of time. The attempt
// deadline closes the socket as well as expiring the context, so the read can
// surface a closed-connection error instead of a deadline error; without this
// the operator would see "network" for a blocked provider, which is exactly the
// failure he needs told apart.
func attemptError(attemptCtx context.Context, err error) error {
	if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
	}
	return err
}

func ensureEDNS0(msg *mdns.Msg, size uint16) {
	if opt := msg.IsEdns0(); opt != nil {
		if opt.UDPSize() < size {
			opt.SetUDPSize(size)
		}
		return
	}
	msg.SetEdns0(size, false)
}
