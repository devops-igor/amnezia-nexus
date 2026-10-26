package naive

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// testRootCAs allows in-process test fixtures to supply an ephemeral root CA
// without altering the public New() constructor signature. In production, this
// remains nil, prompting standard crypto/tls system root verification.
var testRootCAs *x509.CertPool

// Dialer establishes authenticated HTTP/2 or HTTP/3 CONNECT tunnels to a NaiveProxy
// endpoint, satisfying the streambridge.StreamDialer interface.
type Dialer struct {
	endpoint string
	params   models.NaiveProxyParams
	tlsCfg   *tls.Config
	h2Pool   *h2Pool
	h3Pool   *h3Pool
}

// New constructs a new NaiveProxy Dialer with defensive input validation.
func New(endpoint string, p models.NaiveProxyParams) (*Dialer, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("naive: invalid endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return nil, errors.New("naive: endpoint host cannot be empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("naive: invalid endpoint port %q", portStr)
	}

	domain := strings.TrimSpace(p.Domain)
	if domain == "" {
		return nil, errors.New("naive: domain cannot be empty")
	}
	if strings.ContainsAny(domain, " \t\r\n:/\\") {
		return nil, fmt.Errorf("naive: invalid domain name %q", domain)
	}

	if p.Username == "" {
		return nil, errors.New("naive: username cannot be empty")
	}
	if p.Password == "" {
		return nil, errors.New("naive: password cannot be empty")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: domain,
		RootCAs:    testRootCAs,
	}

	d := &Dialer{
		endpoint: endpoint,
		params:   p,
		tlsCfg:   tlsCfg,
		h2Pool:   newH2Pool(),
		h3Pool:   newH3Pool(),
	}

	return d, nil
}

// DialContext establishes a TCP stream tunnel to address through the NaiveProxy endpoint.
// It satisfies streambridge.StreamDialer.
// NaiveProxy only tunnels TCP streams; requests for any other network return an error.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("naive: unsupported network %q (NaiveProxy only tunnels TCP streams)", network)
	}

	if d.params.EnableH3 {
		h3Ctx := ctx
		if deadline, ok := ctx.Deadline(); ok {
			timeout := time.Until(deadline) / 2
			if timeout > 2*time.Second {
				timeout = 2 * time.Second
			}
			if timeout > 0 {
				var cancel context.CancelFunc
				h3Ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
		} else {
			var cancel context.CancelFunc
			h3Ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
		}

		conn, err := d.dialH3(h3Ctx, address)
		if err == nil {
			return conn, nil
		}
		// If the proxy actively rejected with an HTTP status (e.g. 407 auth failure),
		// do not fall through to H2 — propagate the rejection.
		var statusErr *statusError
		if errors.As(err, &statusErr) {
			return nil, statusErr
		}
		// On any transport-level H3 failure (UDP blocked, handshake timeout, network drop),
		// gracefully fall through to H2 without failing the connection.
	}

	return d.dialH2(ctx, address)
}

// Close closes all pooled connections associated with this dialer.
func (d *Dialer) Close() error {
	d.h2Pool.close()
	d.h3Pool.close()
	return nil
}

// basicAuth returns the HTTP Basic authentication credentials formatted for Proxy-Authorization.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
