package naive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type statusError struct {
	statusCode int
	err        error
}

func (e *statusError) Error() string {
	return e.err.Error()
}

func (e *statusError) Unwrap() error {
	return e.err
}

type h3Pool struct {
	mu         sync.Mutex
	quicConn   *quic.Conn
	clientConn *http3.ClientConn
	closed     bool
	inflight   *h3Inflight
}

// h3Inflight coordinates a single QUIC handshake shared by concurrent callers.
// err is written before done is closed.
type h3Inflight struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func newH3Pool() *h3Pool {
	return &h3Pool{}
}

func (p *h3Pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.inflight != nil {
		p.inflight.cancel()
	}
	if p.quicConn != nil {
		_ = p.quicConn.CloseWithError(0, "closed")
		p.quicConn = nil
		p.clientConn = nil
	}
}

func (p *h3Pool) invalidate(clientConn *http3.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clientConn == clientConn {
		if p.quicConn != nil {
			_ = p.quicConn.CloseWithError(0, "reset")
			p.quicConn = nil
		}
		p.clientConn = nil
	}
}

// getH3Conn returns the pooled HTTP/3 connection, dialing at most one new QUIC
// connection at a time. The handshake runs outside h3Pool.mu so that other
// callers stay cancelable and Close can abort it.
func (d *Dialer) getH3Conn(ctx context.Context) (*http3.ClientConn, error) {
	p := d.h3Pool
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if p.clientConn != nil && p.clientConn.Context().Err() == nil {
			cc := p.clientConn
			p.mu.Unlock()
			return cc, nil
		}

		if inf := p.inflight; inf != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-inf.done:
			}
			// A leader aborted by its own context must not fail healthy waiters: retry.
			if inf.err != nil && !errors.Is(inf.err, context.Canceled) && !errors.Is(inf.err, context.DeadlineExceeded) {
				return nil, inf.err
			}
			continue
		}

		dialCtx, cancel := context.WithCancel(ctx)
		inf := &h3Inflight{done: make(chan struct{}), cancel: cancel}
		p.inflight = inf
		p.mu.Unlock()

		return d.dialAndPublishH3(dialCtx, inf)
	}
}

func (d *Dialer) resolveEndpointUDP(ctx context.Context) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(d.endpoint)
	if err != nil {
		return nil, fmt.Errorf("naive: invalid endpoint %q: %w", d.endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("naive: invalid endpoint port %q: %w", portStr, err)
	}

	cleanHost := strings.Trim(host, "[]")
	if ip := net.ParseIP(cleanHost); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("naive: resolve endpoint %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("naive: no IP addresses found for endpoint %s", host)
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

func (d *Dialer) dialAndPublishH3(dialCtx context.Context, inf *h3Inflight) (*http3.ClientConn, error) {
	defer inf.cancel()

	resolvedUDP, err := d.resolveEndpointUDP(dialCtx)
	var quicConn *quic.Conn
	var clientConn *http3.ClientConn
	if err != nil {
		err = fmt.Errorf("naive: quic dial %s: %w", d.endpoint, err)
	} else {
		tlsCfg := d.tlsCfg.Clone()
		tlsCfg.NextProtos = []string{http3.NextProtoH3}

		quicConn, err = quic.DialAddr(dialCtx, resolvedUDP.String(), tlsCfg, &quic.Config{
			KeepAlivePeriod: 15 * time.Second,
		})
		if err != nil {
			err = fmt.Errorf("naive: quic dial %s: %w", d.endpoint, err)
		} else {
			clientConn = (&http3.Transport{}).NewClientConn(quicConn)
		}
	}

	p := d.h3Pool
	p.mu.Lock()
	defer p.mu.Unlock()
	defer close(inf.done)
	p.inflight = nil

	switch {
	case p.closed:
		// Close raced the handshake: discard any late connection.
		if quicConn != nil {
			_ = quicConn.CloseWithError(0, "closed")
		}
		inf.err = net.ErrClosed
	case err != nil:
		inf.err = err
	default:
		p.quicConn = quicConn
		p.clientConn = clientConn
		return clientConn, nil
	}
	return nil, inf.err
}

func (d *Dialer) dialH3(ctx context.Context, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	clientConn, err := d.getH3Conn(ctx)
	if err != nil {
		return nil, err
	}

	reqStream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return nil, fmt.Errorf("naive: open h3 request stream: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "", nil)
	if err != nil {
		_ = reqStream.Close()
		return nil, fmt.Errorf("naive: new h3 connect request: %w", err)
	}
	req.URL = &url.URL{Host: address}
	req.Host = address
	req.Header = make(http.Header)
	req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(d.params.Username, d.params.Password))
	req.Header["User-Agent"] = []string{""}

	stop := context.AfterFunc(ctx, func() {
		reqStream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		reqStream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})

	if err := reqStream.SendRequestHeader(req); err != nil {
		if !stop() {
			_ = reqStream.Close()
			return nil, ctx.Err()
		}
		_ = reqStream.Close()
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return nil, fmt.Errorf("naive: send h3 request headers: %w", err)
	}

	resp, err := reqStream.ReadResponse()
	if !stop() {
		_ = reqStream.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = reqStream.Close()
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return nil, fmt.Errorf("naive: read h3 connect response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = reqStream.Close()
		return nil, &statusError{
			statusCode: resp.StatusCode,
			err:        fmt.Errorf("naive: connect rejected with status %d", resp.StatusCode),
		}
	}

	return &h3Conn{
		stream:     reqStream,
		localAddr:  clientConn.LocalAddr(),
		remoteAddr: clientConn.RemoteAddr(),
	}, nil
}

func (d *Dialer) probeH3(ctx context.Context, camTarget string) (int, error) {
	clientConn, err := d.getH3Conn(ctx)
	if err != nil {
		return 0, err
	}

	reqStream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return 0, err
	}
	defer func() {
		_ = reqStream.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "", nil)
	if err != nil {
		return 0, err
	}
	req.URL = &url.URL{Host: camTarget}
	req.Host = camTarget
	req.Header = make(http.Header)
	req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(d.params.Username, d.params.Password))
	req.Header["User-Agent"] = []string{""}

	stop := context.AfterFunc(ctx, func() {
		reqStream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		reqStream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})

	if err := reqStream.SendRequestHeader(req); err != nil {
		if !stop() {
			return 0, ctx.Err()
		}
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return 0, err
	}

	resp, err := reqStream.ReadResponse()
	if !stop() {
		return 0, ctx.Err()
	}
	if err != nil {
		if clientConn.Context().Err() != nil {
			d.h3Pool.invalidate(clientConn)
		}
		return 0, err
	}

	return resp.StatusCode, nil
}

type h3Conn struct {
	stream     *http3.RequestStream
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     atomic.Bool
}

func (c *h3Conn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.stream.Read(b)
}

func (c *h3Conn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.stream.Write(b)
}

func (c *h3Conn) CloseWrite() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.stream.Close()
}

func (c *h3Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	c.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	return nil
}

func (c *h3Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *h3Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *h3Conn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *h3Conn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *h3Conn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
