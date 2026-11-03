package gatewaydns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// Resolver performs upstream DNS exchanges within strict query and attempt budgets.
type Resolver interface {
	Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

// ResolverConfig defines configuration for UpstreamResolver.
type ResolverConfig struct {
	Upstreams             []netip.AddrPort
	QueryTimeout          time.Duration
	AttemptTimeout        time.Duration
	AllowLoopbackUpstream bool
}

const (
	defaultQueryTimeout   = 4 * time.Second
	defaultAttemptTimeout = 1 * time.Second
	maxUpstreams          = 3
	safeEDNS0Size         = 1232
)

var (
	// ErrNoUpstreams indicates no upstream resolvers were configured.
	ErrNoUpstreams = errors.New("no upstream resolvers configured")
	// ErrTooManyUpstreams indicates more than 3 upstreams were configured.
	ErrTooManyUpstreams = errors.New("at most 3 upstream resolvers allowed")
	// ErrInvalidUpstream indicates an upstream address is non-IPv4, unspecified, or multicast.
	ErrInvalidUpstream = errors.New("invalid upstream resolver address")
	// ErrInvalidRequest indicates a nil or empty DNS request.
	ErrInvalidRequest = errors.New("invalid DNS request")
	// ErrExchangeFailed indicates all upstream attempts failed within the query budget.
	ErrExchangeFailed = errors.New("upstream DNS exchange failed")
)

// UpstreamResolver handles forwarding queries to recursive resolvers with retry and TCP fallback.
type UpstreamResolver struct {
	cfg ResolverConfig
}

// NewUpstreamResolver validates configuration and creates an UpstreamResolver.
func NewUpstreamResolver(cfg ResolverConfig) (*UpstreamResolver, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, ErrNoUpstreams
	}
	if len(cfg.Upstreams) > maxUpstreams {
		return nil, ErrTooManyUpstreams
	}

	for _, u := range cfg.Upstreams {
		if !u.IsValid() || !u.Addr().Is4() {
			return nil, fmt.Errorf("%w: %v must be valid IPv4", ErrInvalidUpstream, u)
		}
		if u.Addr().IsUnspecified() {
			return nil, fmt.Errorf("%w: %v is unspecified", ErrInvalidUpstream, u)
		}
		if u.Addr().IsMulticast() {
			return nil, fmt.Errorf("%w: %v is multicast", ErrInvalidUpstream, u)
		}
		if u.Addr().IsLoopback() && !cfg.AllowLoopbackUpstream {
			return nil, fmt.Errorf("%w: %v is loopback", ErrInvalidUpstream, u)
		}
	}

	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = defaultQueryTimeout
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = defaultAttemptTimeout
	}

	return &UpstreamResolver{cfg: cfg}, nil
}

// Exchange forwards req to configured upstreams within the query budget.
// Handles UDP exchange, retries TC=1 over TCP, and falls back to at most 1 alternate upstream.
func (r *UpstreamResolver) Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, ErrInvalidRequest
	}

	// Bound overall query deadline.
	queryCtx, cancelQuery := context.WithTimeout(ctx, r.cfg.QueryTimeout)
	defer cancelQuery()

	origID := req.Id
	expectedQ := req.Question[0]

	// Determine upstreams to try: primary + at most 1 alternate.
	upstreams := []netip.AddrPort{r.cfg.Upstreams[0]}
	if len(r.cfg.Upstreams) > 1 {
		upstreams = append(upstreams, r.cfg.Upstreams[1])
	}

	var lastErr error
	for i, upstream := range upstreams {
		if queryCtx.Err() != nil {
			return nil, queryCtx.Err()
		}

		resp, err := r.attemptExchange(queryCtx, req, upstream)
		if err != nil {
			lastErr = err
			// Retry on at most 1 alternate upstream on transport/network error.
			continue
		}

		// Validate response envelope.
		if resp == nil || !resp.Response || resp.Opcode != mdns.OpcodeQuery {
			lastErr = fmt.Errorf("%w: invalid response flags from %v", ErrExchangeFailed, upstream)
			continue
		}
		if len(resp.Question) == 0 ||
			!strings.EqualFold(resp.Question[0].Name, expectedQ.Name) ||
			resp.Question[0].Qtype != expectedQ.Qtype ||
			resp.Question[0].Qclass != expectedQ.Qclass {
			lastErr = fmt.Errorf("%w: response question mismatch from %v", ErrExchangeFailed, upstream)
			continue
		}

		// If SERVFAIL and we have an alternate upstream remaining, try alternate.
		if resp.Rcode == mdns.RcodeServerFailure && i < len(upstreams)-1 {
			lastErr = fmt.Errorf("%w: servfail from %v", ErrExchangeFailed, upstream)
			continue
		}

		// Terminal answer (NOERROR, NXDOMAIN, NODATA, etc.) - return to caller.
		resp.Id = origID
		return resp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrExchangeFailed
}

func (r *UpstreamResolver) attemptExchange(ctx context.Context, req *mdns.Msg, upstream netip.AddrPort) (*mdns.Msg, error) {
	attemptDeadline := r.cfg.AttemptTimeout
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

	target := upstream.String()
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
		return nil, err
	}

	// If truncated (TC=1), retry over TCP to the same upstream within remaining budget.
	if resp != nil && resp.Truncated {
		return r.exchangeTCP(ctx, outReq, target)
	}

	return resp, nil
}

func (r *UpstreamResolver) exchangeTCP(ctx context.Context, outReq *mdns.Msg, target string) (*mdns.Msg, error) {
	attemptDeadline := r.cfg.AttemptTimeout
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

	return resp, err
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
