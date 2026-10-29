package vpn

import (
	"errors"
	"io"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
)

// ProxyBackendDevice wraps a streambridge.Device and an optional dialer closer (such as naive.Dialer).
// It satisfies BackendDevice and ensures both the bridge and the underlying connection pool
// are terminated cleanly on Close.
type ProxyBackendDevice struct {
	*streambridge.Device
	closer    io.Closer
	closeOnce sync.Once
	closeErr  error
}

// NewProxyBackendDevice constructs a ProxyBackendDevice wrapping the bridge device and optional dialer closer.
func NewProxyBackendDevice(dev *streambridge.Device, closer io.Closer) *ProxyBackendDevice {
	return &ProxyBackendDevice{
		Device: dev,
		closer: closer,
	}
}

// Static assertion that ProxyBackendDevice and streambridge.Device satisfy BackendDevice.
var (
	_ BackendDevice = (*ProxyBackendDevice)(nil)
	_ BackendDevice = (*streambridge.Device)(nil)
)

// Close gracefully closes both the stream bridge device and the dialer connection pool (if provided).
func (p *ProxyBackendDevice) Close() error {
	p.closeOnce.Do(func() {
		var errs []error
		if p.Device != nil {
			if err := p.Device.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if p.closer != nil {
			if err := p.closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}
