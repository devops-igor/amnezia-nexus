package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
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
	cfg         ServerConfig
	resolver    Resolver
	policy      PolicySource
	globalSem   chan struct{}
	sessionMu   sync.Mutex
	sessionSems map[string]chan struct{}
	closeOnce   sync.Once
	closed      chan struct{}
	wg          sync.WaitGroup

	mu          sync.Mutex
	closing     bool
	activeConns map[net.Conn]*ScopeHandle
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
		sessionSems: make(map[string]chan struct{}),
		closed:      make(chan struct{}),
		activeConns: make(map[net.Conn]*ScopeHandle),
	}, nil
}

// ServeDNSMessage processes a single DNS request, applying inflight limits, upstream resolution,
// response shaping, and route observation.
func (s *Server) ServeDNSMessage(ctx context.Context, session *policy.SessionCache, sessionID string, req *mdns.Msg, isTCP bool) (*mdns.Msg, error) {
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

	// Validate query opcode and class.
	if req.Opcode != mdns.OpcodeQuery {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeNotImplemented)
		return resp, nil
	}
	q := req.Question[0]
	if q.Qclass != mdns.ClassINET {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeRefused)
		return resp, nil
	}
	if q.Qtype == mdns.TypeAXFR || q.Qtype == mdns.TypeIXFR || q.Qtype == mdns.TypeANY {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeRefused)
		return resp, nil
	}

	// Bound per-session and global inflight queries.
	if sessionID != "" {
		s.sessionMu.Lock()
		sem, ok := s.sessionSems[sessionID]
		if !ok {
			sem = make(chan struct{}, s.cfg.MaxInflightPerSession)
			s.sessionSems[sessionID] = sem
		}
		s.sessionMu.Unlock()

		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			resp := new(mdns.Msg)
			resp.SetRcode(req, mdns.RcodeServerFailure)
			return resp, nil
		}
	}

	select {
	case s.globalSem <- struct{}{}:
		defer func() { <-s.globalSem }()
	default:
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		return resp, nil
	}

	recvTime := time.Now()
	resp, err := s.resolver.Exchange(ctx, req)
	if err != nil || resp == nil {
		resp = new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		return resp, nil
	}

	// Observe response and publish client-scoped route evidence if session is active.
	if session != nil && s.policy != nil {
		snapshot := s.policy.Current()
		if snapshot != nil {
			_, _ = ObserveResponse(req, resp, snapshot, session, recvTime, s.cfg.MaxTTL)
		}
	}

	// Shape response: clear AD flag and preserve client ID.
	resp.Id = req.Id
	resp.AuthenticatedData = false

	// Handle UDP truncation.
	if !isTCP {
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

	return resp, nil
}

func (s *Server) serveUDP(ctx context.Context, scope *ScopeHandle, udp net.PacketConn, errCh chan<- error) {
	defer s.wg.Done()
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
		var sessID string
		if scope != nil {
			sc = scope.SessionCache
			sessID = scope.Scope.SessionID
		}

		resp, err := s.ServeDNSMessage(ctx, sc, sessID, req, false)
		if err == nil && resp != nil {
			if out, err := resp.Pack(); err == nil {
				_, _ = udp.WriteTo(out, raddr)
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
		var sessID string
		if scope != nil {
			sc = scope.SessionCache
			sessID = scope.Scope.SessionID
		}

		resp, err := s.ServeDNSMessage(ctx, sc, sessID, req, true)
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
	}
}

func (s *Server) serveTCP(ctx context.Context, scope *ScopeHandle, tcp net.Listener, errCh chan<- error) {
	defer s.wg.Done()
	sem := make(chan struct{}, s.cfg.MaxTCPSessions)
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
		s.wg.Add(1)
		s.mu.Unlock()

		go func(c net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.activeConns, c)
				s.mu.Unlock()
				<-sem
				_ = c.Close()
				s.wg.Done()
			}()
			s.handleTCPConn(ctx, scope, c)
		}(conn)
	}
}

// Serve attaches UDP and TCP listeners to this server, bounded by scope lifetime.
func (s *Server) Serve(ctx context.Context, scope *ScopeHandle, udp net.PacketConn, tcp net.Listener) error {
	s.wg.Add(1)
	defer s.wg.Done()

	owner := scope
	if owner == nil {
		owner = &ScopeHandle{}
	}

	errCh := make(chan error, 2)

	// Unblock and close listeners on server shutdown or context cancellation.
	go func() {
		select {
		case <-s.closed:
		case <-ctx.Done():
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
		s.wg.Add(1)
		go s.serveUDP(ctx, scope, udp, errCh)
	}

	if tcp != nil {
		s.wg.Add(1)
		go s.serveTCP(ctx, owner, tcp, errCh)
	}

	select {
	case <-s.closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
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
