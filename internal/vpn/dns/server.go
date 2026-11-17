package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// PolicySource provides access to the current policy snapshot.
type PolicySource interface {
	Current() *policy.Snapshot
}

// ServerConfig configures Server limits and parameters.
type ServerConfig struct {
	Gateway               netip.AddrPort
	Upstreams             []netip.AddrPort
	QueryTimeout          time.Duration
	AttemptTimeout        time.Duration
	MaxTTL                time.Duration
	MaxInflight           int
	MaxInflightPerSession int
	MaxTCPSessions        int
	AllowLoopbackUpstream bool
}

const (
	defaultMaxInflight           = 64
	defaultMaxInflightPerSession = 4
	defaultMaxTCPSessions        = 32
	defaultMaxTTL                = 3600 * time.Second
)

var (
	// ErrServerClosed indicates the DNS server is shutting down.
	ErrServerClosed = errors.New("dns server is closed")
	// ErrInflightExceeded indicates the query was rejected due to inflight limits.
	ErrInflightExceeded = errors.New("inflight query limit exceeded")
)

// Server coordinates DNS query execution, rate/inflight bounding, response shaping, and policy observation.
type Server struct {
	cfg      ServerConfig
	resolver Resolver
	policy   PolicySource
	observer RouteObserver
	// eventObserver receives one terminal event per client query. It is optional
	// and never on the trust path: recording an event cannot create evidence.
	eventObserver QueryEventObserver
	globalSem     chan struct{}
	sessionMu     sync.Mutex
	sessionSems   map[policy.Scope]chan struct{}
	closeOnce     sync.Once
	closed        chan struct{}
	wg            sync.WaitGroup

	mu          sync.Mutex
	closing     bool
	activeConns map[net.Conn]*ScopeHandle
}

// SetObserver sets the active route observer.
func (s *Server) SetObserver(obs RouteObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = obs
	// A route observer that also understands terminal query events receives them
	// through the same installation, so a caller cannot wire one without the
	// other and end up with answers recorded but failures invisible.
	if events, ok := obs.(QueryEventObserver); ok {
		s.eventObserver = events
	} else if obs == nil {
		s.eventObserver = nil
	}
}

// emitQueryEvent reports one terminal query to the installed observer, if any.
//
// It runs after the delivery attempt and outside every lock; it performs no I/O and
// allocates only the event value. A server without an observer records nothing,
// which is why this cannot be a correctness dependency.
func (s *Server) emitQueryEvent(scope *ScopeHandle, req, resp *mdns.Msg, outcome QueryOutcome, transport string, truncated, delivered bool, recvTime, answeredAt time.Time) {
	if s == nil {
		return
	}
	observer := s.QueryEventObserver()
	if observer == nil {
		return
	}
	event, ok := buildQueryEvent(scope, req, resp, outcome, transport, truncated, delivered, recvTime, answeredAt)
	if !ok {
		return
	}
	observer.ObserveDNSQueryEvent(event)
}

// buildQueryEvent assembles one terminal event, or reports that the query carries
// nothing to record.
func buildQueryEvent(scope *ScopeHandle, req, resp *mdns.Msg, outcome QueryOutcome, transport string, truncated, delivered bool, recvTime, answeredAt time.Time) (QueryEvent, bool) {
	if req == nil || len(req.Question) == 0 {
		return QueryEvent{}, false
	}
	event := QueryEvent{
		Transport:     transport,
		Name:          canonicalEventName(req.Question[0].Name),
		QType:         req.Question[0].Qtype,
		Kind:          outcome.Kind,
		UpstreamError: outcome.UpstreamError,
		Truncated:     truncated,
		Delivered:     delivered,
		ReceivedAt:    recvTime,
		AnsweredAt:    answeredAt,
	}
	if scope != nil {
		event.SessionID = scope.Scope.SessionID
	}
	if resp != nil {
		event.RCode = resp.Rcode
	}
	// A response that was produced but not handed to the client is a different
	// fact from one the consumer received, so the kind says so.
	if !delivered && event.Kind != QueryEventAdmissionRefused && event.Kind != QueryEventInvalidQuery {
		event.Kind = QueryEventDeliveryFailed
	}
	return event, true
}

// rejectBeforeResolution answers the queries this server refuses without asking an
// upstream: a closed server, a cancelled context, an unparseable request and an
// unsupported query. It reports whether it produced the answer.
func (s *Server) rejectBeforeResolution(ctx context.Context, req *mdns.Msg) (*mdns.Msg, QueryOutcome, error, bool) {
	select {
	case <-s.closed:
		return nil, QueryOutcome{}, ErrServerClosed, true
	case <-ctx.Done():
		return nil, QueryOutcome{}, ctx.Err(), true
	default:
	}
	if req == nil || len(req.Question) == 0 {
		return nil, QueryOutcome{}, ErrInvalidRequest, true
	}
	if errResp := validateQuery(req); errResp != nil {
		return errResp, QueryOutcome{Kind: QueryEventInvalidQuery}, nil, true
	}
	return nil, QueryOutcome{}, nil, false
}

// exchangeUpstream performs the upstream exchange and reports a failure as the
// SERVFAIL the client receives, with the exchange's own class. It is separate so the
// decision reads as one admission, one exchange and one shaping step.
func (s *Server) exchangeUpstream(ctx context.Context, req *mdns.Msg) (*mdns.Msg, QueryOutcome, bool) {
	outcome := QueryOutcome{Kind: QueryEventAnswered}
	resp, err := s.resolver.Exchange(ctx, req)
	if err != nil || resp == nil {
		resp = new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		outcome.Kind = QueryEventUpstreamError
		outcome.UpstreamError = classifyUpstreamError(err)
		return resp, outcome, true
	}
	outcome.Kind = queryEventKind(resp)
	return resp, outcome, false
}

// canonicalEventName lowercases and unbounds a stored query name, bounded to the
// DNS name limit so one hostile query cannot inflate a record.
func canonicalEventName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}

// QueryEventObserver returns the installed terminal-event observer, if any.
func (s *Server) QueryEventObserver() QueryEventObserver {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eventObserver
}

// NewServer creates a new Server.
func NewServer(cfg ServerConfig, resolver Resolver, rules PolicySource) (*Server, error) {
	if !cfg.Gateway.IsValid() || !cfg.Gateway.Addr().Is4() || cfg.Gateway.Port() != 53 {
		return nil, errors.New("gateway must have valid IPv4 and port 53")
	}
	if resolver == nil {
		return nil, errors.New("resolver cannot be nil")
	}

	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = defaultQueryTimeout
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = defaultAttemptTimeout
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = defaultMaxTTL
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = defaultMaxInflight
	}
	if cfg.MaxInflightPerSession <= 0 {
		cfg.MaxInflightPerSession = defaultMaxInflightPerSession
	}
	if cfg.MaxTCPSessions <= 0 {
		cfg.MaxTCPSessions = defaultMaxTCPSessions
	}

	return &Server{
		cfg:         cfg,
		resolver:    resolver,
		policy:      rules,
		globalSem:   make(chan struct{}, cfg.MaxInflight),
		sessionSems: make(map[policy.Scope]chan struct{}),
		closed:      make(chan struct{}),
		activeConns: make(map[net.Conn]*ScopeHandle),
	}, nil
}

func toScope(v any) policy.Scope {
	switch s := v.(type) {
	case policy.Scope:
		return s
	case *ScopeHandle:
		if s != nil {
			return s.Scope
		}
		return policy.Scope{}
	case string:
		if s != "" {
			return policy.Scope{SessionID: s, OwnershipEpoch: 1}
		}
		return policy.Scope{}
	default:
		return policy.Scope{}
	}
}

// ObserveResponse evaluates and records route observations into the session cache.
func (s *Server) ObserveResponse(req, resp *mdns.Msg, session *policy.SessionCache, recvTime time.Time) {
	s.ObserveResponseWithSessionID(req, resp, session, "", recvTime)
}

// ObserveResponseWithSessionID records route observations into the session cache and active route observer.
func (s *Server) ObserveResponseWithSessionID(req, resp *mdns.Msg, session *policy.SessionCache, sessionID string, recvTime time.Time) {
	if resp == nil || resp.Truncated || resp.Rcode != mdns.RcodeSuccess || s.policy == nil {
		return
	}
	snapshot := s.policy.Current()
	if snapshot != nil && session != nil {
		_, _ = ObserveResponse(req, resp, snapshot, session, recvTime, s.cfg.MaxTTL)
	}
	if sessionID == "" && session != nil {
		sessionID = session.Scope().SessionID
	}
	s.mu.Lock()
	obs := s.observer
	s.mu.Unlock()
	// A retired scope must not be re-observed by session ID: the observer would
	// allocate a fresh session cache for a session that already released it.
	// Skipping keeps a delayed/in-flight response from resurrecting the scope.
	if obs != nil && sessionID != "" && (session == nil || !session.Retired()) {
		_ = obs.ObserveDNSResponse(sessionID, req, resp)
	}
}

func validateQuery(req *mdns.Msg) *mdns.Msg {
	if req.Opcode != mdns.OpcodeQuery {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeNotImplemented)
		return resp
	}
	q := req.Question[0]
	if q.Qclass != mdns.ClassINET || q.Qtype == mdns.TypeAXFR || q.Qtype == mdns.TypeIXFR || q.Qtype == mdns.TypeANY {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeRefused)
		return resp
	}
	return nil
}

func (s *Server) acquireInflight(ctx context.Context, scope policy.Scope) (func(), bool) {
	if scope.SessionID == "" {
		select {
		case s.globalSem <- struct{}{}:
			return func() { <-s.globalSem }, true
		default:
			return nil, false
		}
	}

	s.sessionMu.Lock()
	sem, ok := s.sessionSems[scope]
	if !ok {
		sem = make(chan struct{}, s.cfg.MaxInflightPerSession)
		s.sessionSems[scope] = sem
		if ctx != nil && ctx.Done() != nil {
			go func(sc policy.Scope, ch chan struct{}, done <-chan struct{}) {
				select {
				case <-done:
				case <-s.closed:
				}
				s.sessionMu.Lock()
				if s.sessionSems[sc] == ch {
					delete(s.sessionSems, sc)
				}
				s.sessionMu.Unlock()
			}(scope, sem, ctx.Done())
		}
	}
	s.sessionMu.Unlock()

	select {
	case sem <- struct{}{}:
	default:
		return nil, false
	}

	select {
	case s.globalSem <- struct{}{}:
		return func() {
			<-s.globalSem
			<-sem
		}, true
	default:
		<-sem
		return nil, false
	}
}

func truncateUDP(req, resp *mdns.Msg) {
	maxBuf := 512
	if opt := req.IsEdns0(); opt != nil {
		bufSize := int(opt.UDPSize())
		if bufSize > safeEDNS0Size {
			bufSize = safeEDNS0Size
		}
		if bufSize > maxBuf {
			maxBuf = bufSize
		}
	}

	if resp.Len() > maxBuf {
		resp.Truncated = true
		resp.Compress = true
		resp.Truncate(maxBuf)
	}
}

// ServeDNSMessage processes a single DNS request, applying inflight limits, upstream resolution,
// and response shaping.
func (s *Server) ServeDNSMessage(ctx context.Context, scope any, req *mdns.Msg, isTCP bool) (*mdns.Msg, error) {
	resp, _, err := s.serveDNSMessageOutcome(ctx, scope, req, isTCP)
	return resp, err
}

// serveDNSMessageOutcome is ServeDNSMessage plus what actually happened: whether the
// query was refused before an upstream, whether the exchange failed and how, and
// whether the reply was shaped. The terminal-event observer needs those facts, and
// the trust path must not learn them: it keeps calling ServeDNSMessage.
func (s *Server) serveDNSMessageOutcome(ctx context.Context, scope any, req *mdns.Msg, isTCP bool) (*mdns.Msg, QueryOutcome, error) {
	if resp, outcome, err, handled := s.rejectBeforeResolution(ctx, req); handled {
		// The refusal keeps its original error, so ServeDNSMessage's contract is
		// unchanged for every caller.
		return resp, outcome, err
	}
	outcome := QueryOutcome{Kind: QueryEventAnswered}

	scopeVal := toScope(scope)
	release, ok := s.acquireInflight(ctx, scopeVal)
	if !ok {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		outcome.Kind = QueryEventAdmissionRefused
		return resp, outcome, nil
	}
	defer release()

	resp, outcome, failed := s.exchangeUpstream(ctx, req)
	if failed {
		return resp, outcome, nil
	}

	// Shape response: clear AD flag and preserve client ID.
	resp.Id = req.Id
	resp.AuthenticatedData = false

	if !isTCP {
		truncateUDP(req, resp)
		if resp.Truncated && outcome.Kind == QueryEventAnswered {
			// The client received a cut answer and must retry over TCP; saying so is
			// the point of the event.
			outcome.Kind = QueryEventTruncated
		}
	}

	return resp, outcome, nil
}

func (s *Server) serveUDP(ctx context.Context, scope *ScopeHandle, udp net.PacketConn, errCh chan<- error, producers *sync.WaitGroup) {
	defer producers.Done()
	buf := make([]byte, 2048)
	for {
		n, raddr, err := udp.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.closed:
			case <-ctx.Done():
			default:
				errCh <- err
			}
			return
		}
		req := new(mdns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}

		var sc *policy.SessionCache
		var scopeVal policy.Scope
		if scope != nil {
			sc = scope.SessionCache
			scopeVal = scope.Scope
		}

		recvTime := time.Now()
		resp, outcome, err := s.serveDNSMessageOutcome(ctx, scopeVal, req, false)
		if err == nil && resp != nil {
			delivered := false
			if out, err := resp.Pack(); err == nil {
				if _, writeErr := udp.WriteTo(out, raddr); writeErr == nil {
					delivered = true
					if sc != nil || s.observer != nil {
						s.ObserveResponseWithSessionID(req, resp, sc, scopeVal.SessionID, recvTime)
					}
				}
			}
			s.emitQueryEvent(scope, req, resp, outcome, "udp", resp.Truncated, delivered, recvTime, time.Now())
		}
	}
}

func (s *Server) handleTCPConn(ctx context.Context, scope *ScopeHandle, c net.Conn) {
	var lenBuf [2]byte
	readTimeout := s.cfg.QueryTimeout
	if readTimeout <= 0 {
		readTimeout = defaultQueryTimeout
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(readTimeout))
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf[:])
		if msgLen < 12 {
			return
		}
		msgBuf := make([]byte, msgLen)
		_ = c.SetReadDeadline(time.Now().Add(readTimeout))
		if _, err := io.ReadFull(c, msgBuf); err != nil {
			return
		}
		req := new(mdns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			return
		}

		var sc *policy.SessionCache
		var scopeVal policy.Scope
		if scope != nil {
			sc = scope.SessionCache
			scopeVal = scope.Scope
		}

		recvTime := time.Now()
		resp, outcome, err := s.serveDNSMessageOutcome(ctx, scopeVal, req, true)
		if err != nil || resp == nil {
			return
		}
		out, err := resp.Pack()
		if err != nil || len(out) > 65535 {
			return
		}
		// #nosec G115 -- out length is validated <= 65535 above
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(out)))
		_ = c.SetWriteDeadline(time.Now().Add(readTimeout))
		delivered := false
		// The length prefix and the body are one response on the wire; the event is
		// only "delivered" when both writes succeeded.
		if _, err := c.Write(lenBuf[:]); err == nil {
			if _, err := c.Write(out); err == nil {
				delivered = true
			}
		}
		s.emitQueryEvent(scope, req, resp, outcome, "tcp", resp.Truncated, delivered, recvTime, time.Now())
		if !delivered {
			return
		}
		if (sc != nil || s.observer != nil) && (scope == nil || !scope.IsRetired()) {
			sID := ""
			if scope != nil {
				sID = scope.Scope.SessionID
			}
			s.ObserveResponseWithSessionID(req, resp, sc, sID, recvTime)
		}
	}
}

func (s *Server) serveTCP(ctx context.Context, scope *ScopeHandle, tcp net.Listener, errCh chan<- error, producers *sync.WaitGroup) {
	defer producers.Done()
	sem := make(chan struct{}, s.cfg.MaxTCPSessions)

	// owned tracks connections accepted by this invocation so the accept loop
	// never returns while one of its handlers is still serving.
	var ownedMu sync.Mutex
	owned := make(map[net.Conn]struct{})
	var handlers sync.WaitGroup

	// Accept can fail for reasons other than shutdown/retirement, so handlers
	// must be unblocked and joined here rather than relying on the caller.
	defer func() {
		ownedMu.Lock()
		for c := range owned {
			_ = c.Close()
		}
		ownedMu.Unlock()
		handlers.Wait()
	}()

	for {
		conn, err := tcp.Accept()
		if err != nil {
			select {
			case <-s.closed:
			case <-ctx.Done():
			default:
				errCh <- err
			}
			return
		}

		select {
		case sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}

		s.mu.Lock()
		if s.closing || ctx.Err() != nil {
			s.mu.Unlock()
			<-sem
			_ = conn.Close()
			return
		}
		s.activeConns[conn] = scope
		s.mu.Unlock()

		ownedMu.Lock()
		owned[conn] = struct{}{}
		ownedMu.Unlock()
		handlers.Add(1)

		go func(c net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.activeConns, c)
				s.mu.Unlock()
				ownedMu.Lock()
				delete(owned, c)
				ownedMu.Unlock()
				<-sem
				_ = c.Close()
				handlers.Done()
			}()
			s.handleTCPConn(ctx, scope, c)
		}(conn)
	}
}

// Serve attaches UDP and TCP listeners to this server, bounded by scope lifetime.
//
// Serve guarantees a producer-ordered teardown: it returns only after its
// listeners are closed AND every goroutine it started (accept/read loops and
// their connection handlers) has finished. Callers that own the backing device
// for these listeners must wait for Serve before closing it, otherwise the
// device can be closed while a listener teardown is still writing to it.
func (s *Server) Serve(ctx context.Context, scope *ScopeHandle, udp net.PacketConn, tcp net.Listener) error {
	s.wg.Add(1)
	defer s.wg.Done()

	owner := scope
	if owner == nil {
		owner = &ScopeHandle{}
	}

	errCh := make(chan error, 2)
	var producers sync.WaitGroup

	// Unblock and close listeners on server shutdown, retirement, or on Serve's
	// own return (a listener error). Completing before Serve returns is what
	// orders listener teardown ahead of any device close by the caller.
	stopCloser := make(chan struct{})
	closerDone := make(chan struct{})
	go func() {
		defer close(closerDone)
		select {
		case <-s.closed:
		case <-ctx.Done():
		case <-stopCloser:
		}
		if scope != nil {
			s.RetireScope(scope.Scope)
		}
		if udp != nil {
			_ = udp.Close()
		}
		if tcp != nil {
			_ = tcp.Close()
		}
		s.mu.Lock()
		closing := s.closing
		if !closing {
			select {
			case <-s.closed:
				closing = true
			default:
			}
		}
		for c, sc := range s.activeConns {
			if closing || sc == owner {
				_ = c.Close()
			}
		}
		s.mu.Unlock()
	}()

	if udp != nil {
		producers.Add(1)
		go s.serveUDP(ctx, scope, udp, errCh, &producers)
	}

	if tcp != nil {
		producers.Add(1)
		go s.serveTCP(ctx, owner, tcp, errCh, &producers)
	}

	var err error
	select {
	case <-s.closed:
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errCh:
	}

	// Order: listeners closed (no new work, no in-flight listener teardown),
	// then producers and their handlers drained. Only then may a caller close
	// the device the listeners write into.
	close(stopCloser)
	<-closerDone
	producers.Wait()

	return err
}

// Shutdown initiates clean shutdown of the Server and waits for active requests to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		close(s.closed)
	})

	s.mu.Lock()
	s.closing = true
	for c := range s.activeConns {
		_ = c.Close()
	}
	s.mu.Unlock()

	s.sessionMu.Lock()
	for sc := range s.sessionSems {
		delete(s.sessionSems, sc)
	}
	s.sessionMu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RetireScope removes any in-flight limiter state associated with the scope.
func (s *Server) RetireScope(scope policy.Scope) {
	s.sessionMu.Lock()
	delete(s.sessionSems, scope)
	s.sessionMu.Unlock()
}

// ActiveSessionLimiters returns the number of active session limiter entries.
func (s *Server) ActiveSessionLimiters() int {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return len(s.sessionSems)
}
