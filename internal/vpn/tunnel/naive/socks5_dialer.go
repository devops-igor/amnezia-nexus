package naive

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// StreamDialer defines the interface for dialing proxied streams, matching streambridge.StreamDialer
// without creating an import cycle.
type StreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Socks5Dialer implements StreamDialer by routing TCP flows
// through a local SOCKS5 proxy listener (such as the supervised naive daemon).
type Socks5Dialer struct {
	addr   string
	dialer proxy.ContextDialer
}

var _ StreamDialer = (*Socks5Dialer)(nil)

// NewSocks5Dialer creates a new StreamDialer backed by the SOCKS5 proxy at addr.
func NewSocks5Dialer(addr string) (*Socks5Dialer, error) {
	if addr == "" {
		return nil, errors.New("naive: empty SOCKS5 address")
	}

	baseDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("naive: failed to initialize SOCKS5 dialer for %s: %w", addr, err)
	}

	cd, ok := baseDialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("naive: SOCKS5 dialer does not implement proxy.ContextDialer")
	}

	return &Socks5Dialer{
		addr:   addr,
		dialer: cd,
	}, nil
}

// DialContext establishes a proxied TCP connection to the specified address.
// NaiveProxy only tunnels TCP streams; any other network produces an error.
func (s *Socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("naive: unsupported network %q (SOCKS5 dialer only tunnels TCP streams)", network)
	}
	return s.dialer.DialContext(ctx, network, address)
}

// SupportsUDP returns false because NaiveProxy and the SOCKS5 proxy tunnel TCP only.
func (s *Socks5Dialer) SupportsUDP() bool {
	return false
}

// Addr returns the loopback SOCKS5 listener address.
func (s *Socks5Dialer) Addr() string {
	return s.addr
}
