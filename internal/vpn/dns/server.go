package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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
	// DefaultMaxInflight bounds how many queries this server resolves at once
	// across every session.
	DefaultMaxInflight = 64
	// DefaultMaxInflightPerSession is the per-session admission budget of a server
	// whose caller declares no producer count and configures no budget.
	//
	// The budget exists so one session cannot own the server, not to model client
	// pacing, and it must cover every producer that can present work for the same
	// session at the same time. A budget below that producer bound admits work the
	// bounded ingress queue already accepted and then answers it with a
	// panel-origin SERVFAIL that never reaches an upstream: indistinguishable from
	// an upstream failure at the client, and enough to break an ordinary browser
	// burst (A, AAAA and HTTPS per name). The intercepted-DNS caller therefore
	// declares its UDP producer count (DeclareUDPProducers), and the effective
	// budget becomes that declaration plus this server's own TCP connection bound
	// (MaxTCPSessions), clamped to DefaultMaxInflight; see sessionBudgetLocked. A
	// caller that configures MaxInflightPerSession explicitly keeps exactly that
	// value. Refusals above the effective budget stay bounded and are counted by
	// cause (see AdmissionRejections).
	DefaultMaxInflightPerSession = 8
	defaultMaxTCPSessions        = 32
	defaultMaxTTL                = 3600 * time.Second
)

var (
	// ErrServerClosed indicates the DNS server is shutting down.
	ErrServerClosed = errors.New("dns server is closed")
	// ErrInflightExceeded indicates the query was rejected due to inflight limits.
	ErrInflightExceeded = errors.New("inflight query limit exceeded")
)

// AdmissionRejections attributes the queries a Server refused before contacting
// any upstream, by the concurrency limit that refused them.
//
// These are panel-side outcomes, not resolver health: a refused query never
// reaches an upstream, so an empty ResolverStatus alongside these counts is not
// a contradiction and must never be read as "the upstream failed" or, worse, as
// "the client was answered". The counts only grow and are read without a lock.
type AdmissionRejections struct {
	// PerSession counts refusals caused by the querying session's own budget.
	PerSession uint64
	// Global counts refusals caused by the server-wide budget.
	Global uint64
}

// admissionOutcome reports which concurrency limit decided a query's admission.
type admissionOutcome int

const (
	admitted admissionOutcome = iota
	refusedPerSession
	refusedGlobal
)

// Server coordinates DNS query execution, rate/inflight bounding, response shaping, and policy observation.
type Server struct {
	cfg         ServerConfig
	resolver    Resolver
	policy      PolicySource
	observer    RouteObserver
	globalSem   chan struct{}
	sessionMu   sync.Mutex
	sessionSems map[policy.Scope]chan struct{}
	closeOnce   sync.Once
	closed      chan struct{}
	wg          sync.WaitGroup

	rejectedPerSession atomic.Uint64
	rejectedGlobal     atomic.Uint64

	// udpProducers is the producer count the calling UDP submission path declared,
	// and perSessionExplicit records whether the caller configured the per-session
	// budget itself. Both are guarded by sessionMu so a declaration and the
	// creation of a scope's budget are ordered against each other.
	udpProducers       int
	perSessionExplicit bool

	mu          sync.Mutex
	closing     bool
	activeConns map[net.Conn]*ScopeHandle
}

// SetObserver sets the active route observer.
func (s *Server) SetObserver(obs RouteObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = obs
}

// applyServerDefaults fills the configuration a Server needs when the caller
// leaves fields unset. It reports whether the caller configured the per-session
// budget itself, because only an unconfigured budget follows the declared
// producer bound.
func applyServerDefaults(cfg *ServerConfig) (perSessionExplicit bool) {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = defaultQueryTimeout
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = defaultAttemptTimeout
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = defaultMaxTTL
	}
	perSessionExplicit = cfg.MaxInflightPerSession > 0
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	if !perSessionExplicit {
		cfg.MaxInflightPerSession = DefaultMaxInflightPerSession
	}
	if cfg.MaxTCPSessions <= 0 {
		cfg.MaxTCPSessions = defaultMaxTCPSessions
	}
	return perSessionExplicit
}

// NewServer creates a new Server.
func NewServer(cfg ServerConfig, resolver Resolver, rules PolicySource) (*Server, error) {
	if !cfg.Gateway.IsValid() || !cfg.Gateway.Addr().Is4() || cfg.Gateway.Port() != 53 {
		return nil, errors.New("gateway must have valid IPv4 and port 53")
	}
	if resolver == nil {
		return nil, errors.New("resolver cannot be nil")
	}

	perSessionExplicit := applyServerDefaults(&cfg)

	return &Server{
		cfg:                cfg,
		resolver:           resolver,
		policy:             rules,
		globalSem:          make(chan struct{}, cfg.MaxInflight),
		sessionSems:        make(map[policy.Scope]chan struct{}),
		closed:             make(chan struct{}),
		activeConns:        make(map[net.Conn]*ScopeHandle),
		perSessionExplicit: perSessionExplicit,
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

// DeclareUDPProducers records how many goroutines the caller's UDP submission
// path can have inside ServeDNSMessage at the same time. Each of them blocks in
// one query until it completes, so together with this server's TCP connection
// bound they are the maximum concurrency one session can legitimately present.
//
// The declaration only raises the budget of an unconfigured per-session limit and
// only ever raises it: a caller's explicit MaxInflightPerSession is never
// overridden, and a later, smaller declaration cannot shrink a live budget. It
// must be made while the calling path is being installed, before its first
// submission, because a scope's budget is fixed when that scope first queries.
// The producer that owns the submission path is the only caller, so a missing
// declaration cannot silently narrow the budget below its own concurrency.
func (s *Server) DeclareUDPProducers(producers int) {
	if s == nil || producers <= 0 {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if producers > s.udpProducers {
		s.udpProducers = producers
	}
}

// sessionBudgetLocked returns the per-session admission budget: the caller's
// configured value when there is one, otherwise the declared UDP producer count
// plus this server's own TCP connection bound. The result never falls below the
// unconfigured default and is clamped to the global budget.
//
// The clamp matters: a session that reaches the global budget cannot be refused
// by its own budget first, so a genuine refusal is always the server-wide cause
// and never a panel-side artifact of a smaller number. Callers must hold
// sessionMu.
func (s *Server) sessionBudgetLocked() int {
	if s.perSessionExplicit {
		return s.cfg.MaxInflightPerSession
	}
	budget := s.cfg.MaxInflightPerSession
	if producers := s.udpProducers + s.cfg.MaxTCPSessions; producers > budget {
		budget = producers
	}
	if budget > s.cfg.MaxInflight {
		budget = s.cfg.MaxInflight
	}
	return budget
}

// SessionBudget returns the effective per-session admission budget. It exists so
// a consumer can assert the budget covers the producer bounds it was told about
// instead of trusting a constant.
func (s *Server) SessionBudget() int {
	if s == nil {
		return 0
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	return s.sessionBudgetLocked()
}

// TCPSessionBudget returns the connection bound this server admits for one
// session's TCP transport, which is one producer of concurrent queries.
func (s *Server) TCPSessionBudget() int {
	if s == nil {
		return 0
	}
	return s.cfg.MaxTCPSessions
}

// sessionSemaphore returns the concurrency budget of one authenticated session,
// creating it — together with its retirement watcher — on first use. Callers
// must not hold sessionMu.
func (s *Server) sessionSemaphore(ctx context.Context, scope policy.Scope) chan struct{} {
	s.sessionMu.Lock()
	sem, ok := s.sessionSems[scope]
	if ok {
		s.sessionMu.Unlock()
		return sem
	}
	sem = make(chan struct{}, s.sessionBudgetLocked())
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
	s.sessionMu.Unlock()
	return sem
}

// acquireInflight admits one query under the session budget and then under the
// server-wide budget. Admission never blocks and never waits: a caller that
// cannot be admitted is refused immediately and reports which limit refused it,
// so the bounded inbound queue — not this limiter — absorbs a burst.
func (s *Server) acquireInflight(ctx context.Context, scope policy.Scope) (func(), admissionOutcome) {
	if scope.SessionID == "" {
		select {
		case s.globalSem <- struct{}{}:
			return func() { <-s.globalSem }, admitted
		default:
			return nil, refusedGlobal
		}
	}

	sem := s.sessionSemaphore(ctx, scope)

	select {
	case sem <- struct{}{}:
	default:
		return nil, refusedPerSession
	}

	select {
	case s.globalSem <- struct{}{}:
		return func() {
			<-s.globalSem
			<-sem
		}, admitted
	default:
		<-sem
		return nil, refusedGlobal
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

// refuseAdmission answers an admission refusal without contacting an upstream
// and attributes it to the limit that refused it, so a panel-origin SERVFAIL is
// never indistinguishable from an upstream failure.
func (s *Server) refuseAdmission(req *mdns.Msg, outcome admissionOutcome) *mdns.Msg {
	switch outcome {
	case refusedPerSession:
		s.rejectedPerSession.Add(1)
	case refusedGlobal:
		s.rejectedGlobal.Add(1)
	}
	resp := new(mdns.Msg)
	resp.SetRcode(req, mdns.RcodeServerFailure)
	return resp
}

// shapeClientResponse rewrites an upstream answer for the client that asked: the
// client's message id, the AD flag the panel cannot vouch for, and UDP
// truncation to the size the client advertised.
func shapeClientResponse(req, resp *mdns.Msg, isTCP bool) *mdns.Msg {
	resp.Id = req.Id
	resp.AuthenticatedData = false
	if !isTCP {
		truncateUDP(req, resp)
	}
	return resp
}

// ServeDNSMessage processes a single DNS request, applying inflight limits, upstream resolution,
// and response shaping.
func (s *Server) ServeDNSMessage(ctx context.Context, scope any, req *mdns.Msg, isTCP bool) (*mdns.Msg, error) {
	select {
	case <-s.closed:
		return nil, ErrServerClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if req == nil || len(req.Question) == 0 {
		return nil, ErrInvalidRequest
	}

	if errResp := validateQuery(req); errResp != nil {
		return errResp, nil
	}

	scopeVal := toScope(scope)
	release, outcome := s.acquireInflight(ctx, scopeVal)
	if outcome != admitted {
		// The refusal is answered here, without an upstream attempt, so it is
		// counted by cause rather than left to look like an upstream SERVFAIL.
		return s.refuseAdmission(req, outcome), nil
	}
	defer release()

	resp, err := s.resolver.Exchange(ctx, req)
	if err != nil || resp == nil {
		resp = new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		return resp, nil
	}

	// Shape response: clear AD flag, preserve the client id and truncate UDP to
	// the size the client advertised.
	return shapeClientResponse(req, resp, isTCP), nil
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
		resp, err := s.ServeDNSMessage(ctx, scopeVal, req, false)
		if err == nil && resp != nil {
			if out, err := resp.Pack(); err == nil {
				if _, err := udp.WriteTo(out, raddr); err == nil && (sc != nil || s.observer != nil) {
					s.ObserveResponseWithSessionID(req, resp, sc, scopeVal.SessionID, recvTime)
				}
			}
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
		resp, err := s.ServeDNSMessage(ctx, scopeVal, req, true)
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
		if _, err := c.Write(lenBuf[:]); err != nil {
			return
		}
		if _, err := c.Write(out); err != nil {
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

// AdmissionRejections returns the queries this server refused without an
// upstream attempt, split by the limit that refused them. The counts only grow,
// so a caller can attribute a refusal without polling resolver health.
func (s *Server) AdmissionRejections() AdmissionRejections {
	return AdmissionRejections{
		PerSession: s.rejectedPerSession.Load(),
		Global:     s.rejectedGlobal.Load(),
	}
}
