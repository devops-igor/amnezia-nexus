package naive

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
}

func newH3Pool() *h3Pool {
	return &h3Pool{}
}

func (p *h3Pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
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

func (d *Dialer) getH3Conn(ctx context.Context) (*http3.ClientConn, error) {
	d.h3Pool.mu.Lock()
	defer d.h3Pool.mu.Unlock()

	if d.h3Pool.clientConn != nil && d.h3Pool.clientConn.Context().Err() == nil {
		return d.h3Pool.clientConn, nil
	}

	tlsCfg := d.tlsCfg.Clone()
	tlsCfg.NextProtos = []string{http3.NextProtoH3}

	quicConn, err := quic.DialAddr(ctx, d.endpoint, tlsCfg, &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("naive: quic dial %s: %w", d.endpoint, err)
	}

	tr := &http3.Transport{}
	clientConn := tr.NewClientConn(quicConn)

	d.h3Pool.quicConn = quicConn
	d.h3Pool.clientConn = clientConn

	return clientConn, nil
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
