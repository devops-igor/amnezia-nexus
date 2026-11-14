package ssh

// Bounded, cancellable SSH transport handshake.
//
// golang.org/x/crypto/ssh builds the transport on a socket it is handed: banner
// exchange, key exchange and authentication are blocking reads performed inside
// NewClientConn. ClientConfig.Timeout is a TCP-establishment budget and is not
// applied there, so a peer that accepts the connection and then says nothing
// keeps the caller blocked for as long as the socket stays open.
//
// That is unacceptable for the durable setup installer, which is a serial
// worker: one nonresponsive node would pin every later approved job and the
// panel's own shutdown. This file therefore owns the complete handshake
// lifetime:
//
//  1. one deadline on the socket covers the whole exchange, taken from the
//     configured connection budget;
//  2. a cancellation watcher closes the in-flight socket when the caller's
//     context ends, so worker cancellation reaches the blocked read instead of
//     only being passed along - and a caller deadline sooner than the configured
//     budget is enforced by that same watcher, which is why no second
//     deadline calculation is needed here;
//  3. the deadline is cleared once the transport is established, because the
//     session that follows is long-lived and must not inherit a handshake-only
//     budget.
//
// Host-key verification is untouched: the configured HostKeyCallback still runs
// inside the handshake and its result is still authoritative.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// defaultConnectTimeout bounds TCP establishment and the SSH handshake when a
// Config does not set a budget of its own.
const defaultConnectTimeout = 15 * time.Second

// handshake completes the SSH transport on an already-dialed socket.
//
// Ownership of conn passes into this function: every error path closes it, and
// on success the returned connection owns it. The caller must not close conn
// itself.
func handshake(
	ctx context.Context,
	conn net.Conn,
	addr string,
	cfg *gossh.ClientConfig,
	timeout time.Duration,
) (gossh.Conn, <-chan gossh.NewChannel, <-chan *gossh.Request, error) {
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, nil, nil, handshakeError(ctx, addr, timeout, err)
	}
	timeout = connectTimeout(timeout)
	if err := boundHandshake(conn, timeout); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}

	watch := watchHandshakeCancel(ctx, conn)
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	watch.stop()

	if err != nil {
		// NewClientConn closes a socket whose handshake failed; closing again
		// keeps a deadline or cancellation abort from leaving a half-open peer.
		_ = conn.Close()
		return nil, nil, nil, handshakeError(ctx, addr, timeout, err)
	}

	// The transport is established, so the handshake budget must not survive
	// into the session that follows it.
	if err := clearHandshakeBound(conn); err != nil {
		_ = sshConn.Close()
		return nil, nil, nil, err
	}
	// A caller that gave up while the handshake was finishing keeps its
	// cancellation: the session is closed rather than handed to a caller that
	// has already stopped waiting.
	if err := abandonIfCancelled(ctx, sshConn); err != nil {
		return nil, nil, nil, handshakeError(ctx, addr, timeout, err)
	}
	return sshConn, chans, reqs, nil
}

// connectTimeout resolves the connection budget, falling back to the package
// default so a caller that set none is still bounded.
func connectTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultConnectTimeout
	}
	return timeout
}

// boundHandshake arms the single deadline that covers banner exchange, key
// exchange and authentication.
func boundHandshake(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to bound the ssh handshake: %w", err)
	}
	return nil
}

// clearHandshakeBound removes the handshake-only deadline from an established
// transport, so the long-lived session is not governed by it.
//
// A peer that closed the socket the moment the handshake finished leaves nothing
// to clear: the deadline went with the socket, and the session's own use will
// report the closure. Failing the connection here would reject a handshake that
// actually succeeded, so only a live socket can report a refusal.
func clearHandshakeBound(conn net.Conn) error {
	err := conn.SetDeadline(time.Time{})
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("failed to clear the ssh handshake deadline: %w", err)
}

// abandonIfCancelled closes a session whose caller has already stopped waiting,
// so a cancellation that lands while the handshake is completing cannot leave a
// canceled attempt holding a usable transport.
func abandonIfCancelled(ctx context.Context, session io.Closer) error {
	if err := ctx.Err(); err != nil {
		_ = session.Close()
		return err
	}
	return nil
}

// handshakeError names the bound that ended a failed handshake, so a paused
// setup job records why the host was abandoned instead of a bare socket error.
func handshakeError(ctx context.Context, addr string, timeout time.Duration, cause error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("ssh handshake with %s canceled: %w", addr, ctxErr)
	}
	var netErr net.Error
	if errors.As(cause, &netErr) && netErr.Timeout() {
		return fmt.Errorf("ssh handshake with %s timed out after %s: %w", addr, timeout, cause)
	}
	return fmt.Errorf("ssh handshake failed with %s: %w", addr, cause)
}

// handshakeCancelWatch closes the in-flight socket when the caller's context
// ends. Closing is what interrupts a blocked read; setting a past deadline
// would not reliably unblock a peer that never writes.
type handshakeCancelWatch struct {
	done     chan struct{}
	finished chan struct{}
}

// watchHandshakeCancel starts the watcher for one handshake.
func watchHandshakeCancel(ctx context.Context, conn net.Conn) *handshakeCancelWatch {
	w := &handshakeCancelWatch{done: make(chan struct{}), finished: make(chan struct{})}
	go func() {
		defer close(w.finished)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-w.done:
		}
	}()
	return w
}

// stop ends the watch and waits for it, so no goroutine outlives the handshake.
func (w *handshakeCancelWatch) stop() {
	close(w.done)
	<-w.finished
}
