package naive

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var (
	h2ReadIdleTimeout = 15 * time.Second
	h2PingTimeout     = 15 * time.Second
	h2SetupTimeout    = 15 * time.Second
	// h2IdleConnTimeout bounds how long a connection with no active streams
	// (notably a retired, saturated-then-drained one) stays open.
	h2IdleConnTimeout = 15 * time.Second
)

type h2Pool struct {
	mu sync.Mutex
	//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
	cc *http2.ClientConn
	//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
	conns      map[*http2.ClientConn]struct{}
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
	inflight   *h2Inflight
}

type h2Inflight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	rawConn net.Conn
	err     error
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func newH2Pool() *h2Pool {
	return &h2Pool{
		conns: make(map[*http2.ClientConn]struct{}),
	}
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func (p *h2Pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.inflight != nil {
		if p.inflight.cancel != nil {
			p.inflight.cancel()
		}
		if p.inflight.rawConn != nil {
			_ = p.inflight.rawConn.Close()
		}
	}
	for cc := range p.conns {
		_ = cc.Close()
	}
	p.conns = make(map[*http2.ClientConn]struct{})
	p.cc = nil
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func (p *h2Pool) invalidate(cc *http2.ClientConn) {
	if cc == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cc == cc {
		p.cc = nil
	}
	delete(p.conns, cc)
	go func() { _ = cc.Shutdown(context.Background()) }()
}

// trackedConns returns a slice of all active and retired connections currently tracked by the pool.
//
//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func (p *h2Pool) trackedConns() []*http2.ClientConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	res := make([]*http2.ClientConn, 0, len(p.conns))
	for cc := range p.conns {
		res = append(res, cc)
	}
	return res
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func (d *Dialer) getH2Conn(ctx context.Context) (*http2.ClientConn, net.Addr, net.Addr, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}

		d.h2Pool.mu.Lock()
		if d.h2Pool.closed {
			d.h2Pool.mu.Unlock()
			return nil, nil, nil, net.ErrClosed
		}

		if d.h2Pool.conns == nil {
			d.h2Pool.conns = make(map[*http2.ClientConn]struct{})
		}

		for c := range d.h2Pool.conns {
			if c.State().Closed {
				delete(d.h2Pool.conns, c)
			}
		}

		if d.h2Pool.cc != nil && d.h2Pool.cc.CanTakeNewRequest() {
			cc := d.h2Pool.cc
			local := d.h2Pool.localAddr
			remote := d.h2Pool.remoteAddr
			d.h2Pool.mu.Unlock()
			return cc, local, remote, nil
		}

		if d.h2Pool.inflight != nil {
			inf := d.h2Pool.inflight
			d.h2Pool.mu.Unlock()

			select {
			case <-ctx.Done():
				return nil, nil, nil, ctx.Err()
			case <-inf.done:
				if inf.err != nil {
					if errors.Is(inf.err, context.Canceled) || errors.Is(inf.err, context.DeadlineExceeded) {
						if ctx.Err() != nil {
							return nil, nil, nil, ctx.Err()
						}
						continue
					}
					return nil, nil, nil, inf.err
				}
				continue
			}
		}

		// No in-flight dial; become the dialer outside pool lock.
		dialCtx, dialCancel := context.WithTimeout(ctx, h2SetupTimeout)
		inf := &h2Inflight{
			done:   make(chan struct{}),
			cancel: dialCancel,
		}
		d.h2Pool.inflight = inf
		d.h2Pool.mu.Unlock()

		return d.dialAndPublishH2(dialCtx, dialCancel, inf)
	}
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func (d *Dialer) dialAndPublishH2(dialCtx context.Context, dialCancel context.CancelFunc, inf *h2Inflight) (*http2.ClientConn, net.Addr, net.Addr, error) {
	defer dialCancel()
	defer func() {
		d.h2Pool.mu.Lock()
		if d.h2Pool.inflight == inf {
			d.h2Pool.inflight = nil
		}
		select {
		case <-inf.done:
		default:
			close(inf.done)
		}
		d.h2Pool.mu.Unlock()
	}()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", d.endpoint)
	if err != nil {
		d.h2Pool.mu.Lock()
		if d.h2Pool.closed {
			inf.err = net.ErrClosed
		} else {
			inf.err = fmt.Errorf("naive: dial tcp %s: %w", d.endpoint, err)
		}
		d.h2Pool.mu.Unlock()
		return nil, nil, nil, inf.err
	}

	d.h2Pool.mu.Lock()
	if d.h2Pool.closed {
		d.h2Pool.mu.Unlock()
		_ = rawConn.Close()
		inf.err = net.ErrClosed
		return nil, nil, nil, net.ErrClosed
	}
	inf.rawConn = rawConn
	d.h2Pool.mu.Unlock()

	tlsCfg := d.tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"h2"}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close()
		d.h2Pool.mu.Lock()
		if d.h2Pool.closed {
			inf.err = net.ErrClosed
		} else {
			inf.err = fmt.Errorf("naive: tls handshake %s: %w", d.endpoint, err)
		}
		d.h2Pool.mu.Unlock()
		return nil, nil, nil, inf.err
	}

	cs := tlsConn.ConnectionState()
	if cs.NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		d.h2Pool.mu.Lock()
		if d.h2Pool.closed {
			inf.err = net.ErrClosed
		} else {
			inf.err = fmt.Errorf("naive: negotiated unexpected protocol %q, want h2", cs.NegotiatedProtocol)
		}
		d.h2Pool.mu.Unlock()
		return nil, nil, nil, inf.err
	}

	//nolint:staticcheck // SA1019: x/net/http2.Transport.NewClientConn required for raw TLS connection wrapping
	t := &http2.Transport{
		ReadIdleTimeout: h2ReadIdleTimeout,
		PingTimeout:     h2PingTimeout,
		IdleConnTimeout: h2IdleConnTimeout,
	}
	//nolint:staticcheck // SA1019: x/net/http2.Transport.NewClientConn required for raw TLS connection wrapping
	cc, err := t.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		d.h2Pool.mu.Lock()
		if d.h2Pool.closed {
			inf.err = net.ErrClosed
		} else {
			inf.err = fmt.Errorf("naive: create http2 client conn: %w", err)
		}
		d.h2Pool.mu.Unlock()
		return nil, nil, nil, inf.err
	}

	d.h2Pool.mu.Lock()
	if d.h2Pool.closed {
		d.h2Pool.mu.Unlock()
		_ = cc.Close()
		inf.err = net.ErrClosed
		return nil, nil, nil, net.ErrClosed
	}

	d.h2Pool.cc = cc
	d.h2Pool.conns[cc] = struct{}{}
	d.h2Pool.localAddr = tlsConn.LocalAddr()
	d.h2Pool.remoteAddr = tlsConn.RemoteAddr()
	localAddr := d.h2Pool.localAddr
	remoteAddr := d.h2Pool.remoteAddr
	d.h2Pool.mu.Unlock()

	return cc, localAddr, remoteAddr, nil
}

func (d *Dialer) dialH2(ctx context.Context, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cc, localAddr, remoteAddr, err := d.getH2Conn(ctx)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	reqCtx, reqCancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, reqCancel)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, "", pr)
	if err != nil {
		_ = stop()
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("naive: new h2 connect request: %w", err)
	}
	req.URL = &url.URL{Host: address}
	req.Host = address
	req.Header = make(http.Header)
	req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(d.params.Username, d.params.Password))
	req.Header["User-Agent"] = []string{""}

	resp, err := cc.RoundTrip(req)
	if !stop() {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("naive: h2 roundtrip: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		reqCancel()
		_ = pr.Close()
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("naive: connect rejected with status %d", resp.StatusCode)
	}

	dr := newDeadlineReader(resp.Body)
	return &h2Conn{
		dr:         dr,
		pw:         pw,
		resp:       resp,
		cancel:     reqCancel,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, nil
}

func (d *Dialer) probeH2(ctx context.Context, camTarget string) (int, error) {
	cc, _, _, err := d.getH2Conn(ctx)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "", http.NoBody)
	if err != nil {
		return 0, err
	}
	req.URL = &url.URL{Host: camTarget}
	req.Host = camTarget
	req.Header = make(http.Header)
	req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(d.params.Username, d.params.Password))
	req.Header["User-Agent"] = []string{""}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		if !cc.CanTakeNewRequest() {
			d.h2Pool.invalidate(cc)
		}
		return 0, err
	}
	_ = resp.Body.Close()

	return resp.StatusCode, nil
}

type deadlineReader struct {
	r        io.ReadCloser
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	err      error
	closed   bool
	deadline time.Time
}

func newDeadlineReader(r io.ReadCloser) *deadlineReader {
	dr := &deadlineReader{r: r}
	dr.cond = sync.NewCond(&dr.mu)
	go dr.readLoop()
	return dr
}

func (dr *deadlineReader) readLoop() {
	chunk := make([]byte, 32*1024)
	for {
		n, err := dr.r.Read(chunk)
		dr.mu.Lock()
		if n > 0 {
			dr.buf = append(dr.buf, chunk[:n]...)
			dr.cond.Broadcast()
		}
		if err != nil {
			dr.err = err
			dr.cond.Broadcast()
			dr.mu.Unlock()
			return
		}
		for len(dr.buf) > 512*1024 && !dr.closed {
			dr.cond.Wait()
		}
		if dr.closed {
			dr.mu.Unlock()
			return
		}
		dr.mu.Unlock()
	}
}

func (dr *deadlineReader) Read(p []byte) (int, error) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	for {
		if len(dr.buf) > 0 {
			n := copy(p, dr.buf)
			dr.buf = dr.buf[n:]
			dr.cond.Broadcast()
			return n, nil
		}
		if dr.err != nil {
			return 0, dr.err
		}
		if dr.closed {
			return 0, net.ErrClosed
		}
		if !dr.deadline.IsZero() {
			now := time.Now()
			if !now.Before(dr.deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			d := dr.deadline.Sub(now)
			stop := time.AfterFunc(d, func() {
				dr.mu.Lock()
				dr.cond.Broadcast()
				dr.mu.Unlock()
			})
			dr.cond.Wait()
			stop.Stop()
		} else {
			dr.cond.Wait()
		}
	}
}

func (dr *deadlineReader) SetReadDeadline(t time.Time) error {
	dr.mu.Lock()
	dr.deadline = t
	dr.cond.Broadcast()
	dr.mu.Unlock()
	return nil
}

func (dr *deadlineReader) Close() error {
	dr.mu.Lock()
	if dr.closed {
		dr.mu.Unlock()
		return nil
	}
	dr.closed = true
	dr.cond.Broadcast()
	dr.mu.Unlock()
	return dr.r.Close()
}

type h2Conn struct {
	dr         *deadlineReader
	pw         *io.PipeWriter
	resp       *http.Response
	cancel     context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr

	mu            sync.Mutex
	writeDeadline time.Time
	writeTimer    *time.Timer
	writing       int
	wdExpired     bool
	closed        bool
}

func (c *h2Conn) Read(p []byte) (int, error) {
	return c.dr.Read(p)
}

func (c *h2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if c.wdExpired || (!c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline)) {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	c.writing++
	c.mu.Unlock()

	n, err := c.pw.Write(p)

	c.mu.Lock()
	c.writing--
	expired := c.wdExpired
	c.mu.Unlock()
	if err != nil && expired {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

// expireWrite aborts a Write blocked past the write deadline. io.Pipe offers no
// deadline, so the request body is failed instead; that resets only this stream
// (a partially written stream cannot be resumed anyway), siblings are unaffected.
func (c *h2Conn) expireWrite() {
	c.mu.Lock()
	if c.closed || c.writing == 0 || c.writeDeadline.IsZero() || time.Now().Before(c.writeDeadline) {
		c.mu.Unlock()
		return
	}
	c.wdExpired = true
	c.mu.Unlock()
	_ = c.pw.CloseWithError(os.ErrDeadlineExceeded)
	// The transport may be parked in flow control, not reading the pipe: reset the stream.
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.dr.Close()
}

func (c *h2Conn) CloseWrite() error {
	return c.pw.Close()
}

func (c *h2Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
	}
	err1 := c.pw.Close()
	err2 := c.dr.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *h2Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *h2Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *h2Conn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *h2Conn) SetReadDeadline(t time.Time) error {
	return c.dr.SetReadDeadline(t)
}

func (c *h2Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if !t.IsZero() && !c.closed {
		c.writeTimer = time.AfterFunc(time.Until(t), c.expireWrite)
	}
	return nil
}
