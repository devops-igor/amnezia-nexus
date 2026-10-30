package streambridge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// StreamDialer opens one proxied stream per client flow. Network is "tcp"
// or "udp"; address is the client's destination "host:port". For "udp",
// the returned net.Conn is datagram-oriented: one Write is one datagram
// and one Read returns one datagram.
type StreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

const (
	tcpBufferSize = 32 * 1024
	udpBufferSize = 64 * 1024
)

var (
	tcpBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpBufferSize)
			return &b
		},
	}
	udpBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, udpBufferSize)
			return &b
		},
	}
)

func (d *Device) acquire() bool {
	d.gateMu.RLock()
	defer d.gateMu.RUnlock()

	if d.closed.Load() || d.ctx.Err() != nil {
		return false
	}
	select {
	case d.slots <- struct{}{}:
		d.wg.Add(1)
		d.stats.flowsTotal.Add(1)
		return true
	default:
		d.stats.flowsRejected.Add(1)
		return false
	}
}

func (d *Device) release() {
	<-d.slots
	d.wg.Done()
}

func (d *Device) onTCP(r *tcp.ForwarderRequest) {
	if !d.acquire() {
		r.Complete(true) // reject new flow with RST
		return
	}

	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	dialCtx, cancel := context.WithTimeout(d.ctx, d.cfg.DialTimeout)
	outConn, err := d.dialer.DialContext(dialCtx, "tcp", dst)
	cancel()
	if err != nil {
		d.stats.dialFailures.Add(1)
		d.release()
		r.Complete(true)
		return
	}
	d.stats.lastHandshakeNano.Store(time.Now().UnixNano())

	d.gateMu.RLock()
	closed := d.closed.Load() || d.ctx.Err() != nil
	if !closed {
		d.pendingHandshakes.Add(1)
	}
	d.gateMu.RUnlock()

	if closed {
		_ = outConn.Close()
		d.release()
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := func() (tcpip.Endpoint, tcpip.Error) {
		defer d.pendingHandshakes.Add(-1)
		if d.beforeCreateEndpointHook != nil {
			d.beforeCreateEndpointHook()
		}
		return r.CreateEndpoint(&wq)
	}()
	if tcpipErr != nil {
		_ = outConn.Close()
		d.release()
		r.Complete(true)
		return
	}
	r.Complete(false)

	if d.closed.Load() || d.ctx.Err() != nil {
		ep.Abort()
		ep.Close()
		_ = outConn.Close()
		d.release()
		return
	}

	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(60 * time.Second)
	_ = ep.SetSockOpt(&idle)
	interval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	_ = ep.SetSockOpt(&interval)
	_ = ep.SetSockOptInt(tcpip.KeepaliveCountOption, 4)

	if tc, ok := outConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(60 * time.Second)
	}

	inConn := gonet.NewTCPConn(&wq, ep)

	go d.runTCPFlow(inConn, outConn)
}

func (d *Device) runTCPFlow(inConn *gonet.TCPConn, outConn net.Conn) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = inConn.Close()
			_ = outConn.Close()
		})
	}

	var (
		halfCloseMu    sync.Mutex
		halfCloseTimer *time.Timer
	)
	startHalfCloseTimer := func() {
		halfCloseMu.Lock()
		defer halfCloseMu.Unlock()
		if halfCloseTimer == nil {
			halfCloseTimer = time.AfterFunc(d.cfg.TCPHalfCloseTimeout, closeBoth)
		}
	}
	stopHalfCloseTimer := func() {
		halfCloseMu.Lock()
		defer halfCloseMu.Unlock()
		if halfCloseTimer != nil {
			halfCloseTimer.Stop()
		}
	}

	stopAfter := context.AfterFunc(d.ctx, closeBoth)
	defer func() {
		stopAfter()
		stopHalfCloseTimer()
		closeBoth()
		d.release()
	}()

	var copyWg sync.WaitGroup
	copyWg.Add(2)

	// client -> outbound
	go func() {
		defer copyWg.Done()
		bufPtr := tcpBufPool.Get().(*[]byte)
		defer tcpBufPool.Put(bufPtr)
		buf := *bufPtr

		_, err := io.CopyBuffer(outConn, inConn, buf)
		if err != nil {
			closeBoth()
			return
		}

		if cw, ok := outConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		_ = outConn.SetReadDeadline(time.Now().Add(d.cfg.TCPHalfCloseTimeout))
		startHalfCloseTimer()
	}()

	// outbound -> client
	go func() {
		defer copyWg.Done()
		bufPtr := tcpBufPool.Get().(*[]byte)
		defer tcpBufPool.Put(bufPtr)
		buf := *bufPtr

		_, err := io.CopyBuffer(inConn, outConn, buf)
		if err != nil {
			closeBoth()
			return
		}

		_ = inConn.CloseWrite()
		_ = inConn.SetReadDeadline(time.Now().Add(d.cfg.TCPHalfCloseTimeout))
		startHalfCloseTimer()
	}()

	copyWg.Wait()
}

func (d *Device) onUDP(r *udp.ForwarderRequest) {
	if !d.acquire() {
		return // drop packet without creating endpoint
	}

	if d.closed.Load() || d.ctx.Err() != nil {
		d.release()
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		d.release()
		return
	}

	inConn := gonet.NewUDPConn(&wq, ep)
	id := r.ID()

	if d.closed.Load() || d.ctx.Err() != nil {
		_ = inConn.Close()
		d.release()
		return
	}

	if id.LocalPort == 53 {
		go d.runDNSOverTCPFlow(inConn, id)
		return
	}

	go d.runUDPFlow(inConn, id)
}

func (d *Device) runUDPFlow(inConn *gonet.UDPConn, id stack.TransportEndpointID) {
	defer func() {
		d.release()
	}()

	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	dialCtx, cancel := context.WithTimeout(d.ctx, d.cfg.DialTimeout)
	outConn, err := d.dialer.DialContext(dialCtx, "udp", dst)
	cancel()
	if err != nil {
		d.stats.dialFailures.Add(1)
		_ = inConn.Close()
		return
	}
	d.stats.lastHandshakeNano.Store(time.Now().UnixNano())

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = inConn.Close()
			_ = outConn.Close()
		})
	}

	stopAfter := context.AfterFunc(d.ctx, closeBoth)
	defer func() {
		stopAfter()
		closeBoth()
	}()

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	var pumpWg sync.WaitGroup
	pumpWg.Add(2)

	// client -> outbound
	go func() {
		defer pumpWg.Done()
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			_ = inConn.SetReadDeadline(time.Now().Add(d.cfg.UDPIdleTimeout))
			n, err := inConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) >= d.cfg.UDPIdleTimeout {
						closeBoth()
						return
					}
					continue
				}
				closeBoth()
				return
			}

			lastActivity.Store(time.Now().UnixNano())
			if _, err := outConn.Write(buf[:n]); err != nil {
				closeBoth()
				return
			}
		}
	}()

	// outbound -> client
	go func() {
		defer pumpWg.Done()
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			_ = outConn.SetReadDeadline(time.Now().Add(d.cfg.UDPIdleTimeout))
			n, err := outConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) >= d.cfg.UDPIdleTimeout {
						closeBoth()
						return
					}
					continue
				}
				closeBoth()
				return
			}

			lastActivity.Store(time.Now().UnixNano())
			if _, err := inConn.Write(buf[:n]); err != nil {
				closeBoth()
				return
			}
		}
	}()

	pumpWg.Wait()
}

func (d *Device) runDNSOverTCPFlow(inConn *gonet.UDPConn, id stack.TransportEndpointID) {
	defer func() {
		d.release()
	}()

	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	dialCtx, cancel := context.WithTimeout(d.ctx, d.cfg.DialTimeout)
	outConn, err := d.dialer.DialContext(dialCtx, "tcp", dst)
	cancel()
	if err != nil {
		d.stats.dialFailures.Add(1)
		_ = inConn.Close()
		return
	}
	d.stats.lastHandshakeNano.Store(time.Now().UnixNano())

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = inConn.Close()
			_ = outConn.Close()
		})
	}

	stopAfter := context.AfterFunc(d.ctx, closeBoth)
	defer func() {
		stopAfter()
		closeBoth()
	}()

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	var pumpWg sync.WaitGroup
	pumpWg.Add(2)

	// client UDP -> outbound TCP: translate UDP DNS datagram into RFC 1035 / RFC 7766 2-byte length-prefixed stream
	go func() {
		defer pumpWg.Done()
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			_ = inConn.SetReadDeadline(time.Now().Add(d.cfg.UDPIdleTimeout))
			n, err := inConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) >= d.cfg.UDPIdleTimeout {
						closeBoth()
						return
					}
					continue
				}
				closeBoth()
				return
			}

			if n <= 0 || n > 65535 {
				continue
			}

			lastActivity.Store(time.Now().UnixNano())
			var lenBuf [2]byte
			//nolint:gosec // G115: n is bounded by n <= 65535 check above
			binary.BigEndian.PutUint16(lenBuf[:], uint16(n))

			_ = outConn.SetWriteDeadline(time.Now().Add(d.cfg.DialTimeout))
			if _, err := outConn.Write(lenBuf[:]); err != nil {
				closeBoth()
				return
			}
			if _, err := outConn.Write(buf[:n]); err != nil {
				closeBoth()
				return
			}
		}
	}()

	// outbound TCP -> client UDP: read RFC 1035 / RFC 7766 2-byte length-prefixed stream and return DNS response datagram
	go func() {
		defer pumpWg.Done()
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr

		var lenBuf [2]byte
		for {
			_ = outConn.SetReadDeadline(time.Now().Add(d.cfg.UDPIdleTimeout))
			if _, err := io.ReadFull(outConn, lenBuf[:]); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) >= d.cfg.UDPIdleTimeout {
						closeBoth()
						return
					}
					continue
				}
				closeBoth()
				return
			}

			respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if respLen == 0 || respLen > len(buf) {
				closeBoth()
				return
			}

			if _, err := io.ReadFull(outConn, buf[:respLen]); err != nil {
				closeBoth()
				return
			}

			lastActivity.Store(time.Now().UnixNano())
			if _, err := inConn.Write(buf[:respLen]); err != nil {
				closeBoth()
				return
			}
		}
	}()

	pumpWg.Wait()
}
