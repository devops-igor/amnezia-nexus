package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ProbeOptions configures the TLS probe behavior.
type ProbeOptions struct {
	Timeout     time.Duration
	RootCAs     *x509.CertPool
	Dialer      *net.Dialer
	TargetIP    net.IP
	Port        int
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ProbeResult contains TLS handshake and ALPN verification details.
type ProbeResult struct {
	Domain    string        `json:"domain"`
	RTT       time.Duration `json:"rtt"`
	RTTMS     int64         `json:"rtt_ms"`
	TLS13     bool          `json:"tls13"`
	ALPN      string        `json:"alpn"`
	CertValid bool          `json:"cert_valid"`
	Issuer    string        `json:"issuer,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// ProbeTLSH2 performs a TLS 1.3 handshake with ALPN "h2" negotiation.
// When opts.TargetIP is specified, the probe connects directly to net.JoinHostPort(candIP.String(), "443")
// while setting tls.Config.ServerName to domain. This ensures that the TLS handshake probes the exact IP
// that passed geo proximity checks rather than re-resolving the domain.
func ProbeTLSH2(ctx context.Context, domain string, opts ProbeOptions) ProbeResult {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}

	portStr := "443"
	if opts.Port > 0 {
		portStr = strconv.Itoa(opts.Port)
	}

	targetAddr := net.JoinHostPort(domain, portStr)
	serverName := domain
	if len(opts.TargetIP) > 0 {
		targetAddr = net.JoinHostPort(opts.TargetIP.String(), portStr)
		if h, _, err := net.SplitHostPort(domain); err == nil {
			serverName = h
		}
	} else if h, p, err := net.SplitHostPort(domain); err == nil {
		targetAddr = net.JoinHostPort(h, p)
		serverName = h
	}

	candCtx, candCancel := context.WithTimeout(ctx, timeout)
	defer candCancel()

	start := time.Now()
	dialContext := dialer.DialContext
	if opts.DialContext != nil {
		dialContext = opts.DialContext
	}
	rawConn, err := dialContext(candCtx, "tcp", targetAddr)
	if err != nil {
		return ProbeResult{
			Domain: domain,
			Error:  fmt.Sprintf("tcp dial failed: %v", err),
		}
	}
	defer func() {
		_ = rawConn.Close()
	}()

	tlsCfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    opts.RootCAs,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(candCtx); err != nil {
		return ProbeResult{
			Domain: domain,
			Error:  fmt.Sprintf("tls handshake failed: %v", err),
		}
	}

	rtt := time.Since(start)
	cs := tlsConn.ConnectionState()

	if cs.Version != tls.VersionTLS13 {
		return ProbeResult{
			Domain: domain,
			RTT:    rtt,
			RTTMS:  rtt.Milliseconds(),
			Error:  fmt.Sprintf("unsupported TLS version 0x%04x (requires TLS 1.3)", cs.Version),
		}
	}

	if cs.NegotiatedProtocol != "h2" {
		return ProbeResult{
			Domain: domain,
			RTT:    rtt,
			RTTMS:  rtt.Milliseconds(),
			TLS13:  true,
			ALPN:   cs.NegotiatedProtocol,
			Error:  fmt.Sprintf("negotiated ALPN %q instead of h2", cs.NegotiatedProtocol),
		}
	}

	certValid := len(cs.VerifiedChains) > 0
	issuer := ""
	if certValid && len(cs.PeerCertificates) > 0 {
		issuer = cs.PeerCertificates[0].Issuer.CommonName
	}

	return ProbeResult{
		Domain:    domain,
		RTT:       rtt,
		RTTMS:     rtt.Milliseconds(),
		TLS13:     true,
		ALPN:      cs.NegotiatedProtocol,
		CertValid: certValid,
		Issuer:    issuer,
	}
}
