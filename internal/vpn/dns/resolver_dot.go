package gatewaydns

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file implements DNS over TLS (RFC 7858) for one configured upstream
// entry. It is the only place a query leaves the resolver encrypted.
//
// Properties the design keeps:
//   - The query and its answer travel over one TLS connection. There is no
//     plaintext attempt, no UDP, and no port-53 retry for a DoT entry: the entry
//     either completes the exchange over TLS or fails.
//   - Verification is never skipped. The entry's own address supplies both the
//     SNI and the verified name, so a hostname is checked as a name and an IP
//     literal is checked against an IP SAN. A nil trust store means the system
//     store, which is what production uses.
//   - The handshake and the exchange share the resolver's existing per-attempt
//     budget, so a peer that accepts TCP and then stalls is reported as a
//     timeout rather than holding the query until the overall deadline.

// dotFailure is an attempt error that carries the operator-facing failure kind.
// The resolver's status reports the kind, so a certificate rejection, a pin
// mismatch and a broken handshake stay distinguishable from a timeout. Both
// encrypted transports return it; the name predates DoH.
type dotFailure struct {
	kind FailureKind
	err  error
}

// Error renders the underlying cause.
func (e *dotFailure) Error() string { return e.err.Error() }

// Unwrap exposes the underlying cause to errors.Is / errors.As.
func (e *dotFailure) Unwrap() error { return e.err }

// dialDoTDefault opens the TCP connection a DoT exchange wraps in TLS. It is
// the production dialer; the resolver keeps it in a field so a test can reach a
// local listener through a hostname entry.
func dialDoTDefault(ctx context.Context, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", address)
}

// dotServerName is the name TLS verifies and offers as SNI: the entry's own
// address without the presentation-only trailing dot. For an IP literal this
// makes crypto/tls verify the certificate's IP SAN and send no SNI, which is
// exactly the RFC 7858 behavior for address-configured servers.
func dotServerName(upstream policy.Upstream) string {
	return strings.TrimSuffix(upstream.Address, ".")
}

// exchangeDoT performs one DNS-over-TLS exchange inside the attempt budget.
func (r *UpstreamResolver) exchangeDoT(ctx context.Context, req *mdns.Msg, upstream policy.Upstream) (*mdns.Msg, error) {
	budget := r.attemptBudget(ctx)
	if budget <= 0 {
		return nil, context.DeadlineExceeded
	}
	attemptCtx, cancelAttempt := context.WithTimeout(ctx, budget)
	defer cancelAttempt()

	pin, err := upstream.SPKIPinDigest()
	if err != nil {
		// A validated entry cannot reach this, and an unverifiable pin must never
		// mean "no pin", so the exchange is refused instead of unpinned.
		return nil, &dotFailure{kind: FailureCertificate, err: fmt.Errorf("upstream %s: unusable SPKI pin: %w", upstream.String(), err)}
	}

	conn, state, err := r.dialTLS(attemptCtx, upstream, nil)
	if err != nil {
		return nil, classifyDoTFailure(attemptCtx, err)
	}
	defer func() { _ = conn.Close() }()

	if len(pin) > 0 {
		if err := verifySPKIPin(state, pin); err != nil {
			return nil, err
		}
	}

	outReq := req.Copy()
	outReq.Id = mdns.Id()
	ensureEDNS0(outReq, safeEDNS0Size)

	// Reuse the DNS client's length-prefixed framing over the verified TLS
	// connection: TCP and TLS share RFC 1035 section 4.2.2 framing.
	client := &mdns.Client{Net: "tcp-tls", Timeout: budget}
	stopAfter := context.AfterFunc(attemptCtx, func() { _ = conn.Close() })
	resp, _, err := client.ExchangeWithConnContext(attemptCtx, outReq, &mdns.Conn{Conn: conn})
	stopAfter()
	if err != nil {
		return nil, attemptError(attemptCtx, err)
	}
	return resp, nil
}

// dialTLS opens the TCP connection and completes the TLS handshake within ctx,
// returning the verified connection and its state. It is the one handshake body
// both encrypted transports share: DoT offers no ALPN protocol (nextProtos nil)
// and DoH offers HTTP/2 only, so the chain, name and trust-store rules cannot
// differ between them.
func (r *UpstreamResolver) dialTLS(ctx context.Context, upstream policy.Upstream, nextProtos []string) (*tls.Conn, tls.ConnectionState, error) {
	rawConn, err := r.dotDial(ctx, upstream.HostPort())
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	conn := tls.Client(rawConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: dotServerName(upstream),
		RootCAs:    r.tlsRootCAs,
		NextProtos: nextProtos,
	})
	stopAfter := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err = conn.HandshakeContext(ctx)
	stopAfter()
	if err != nil {
		_ = conn.Close()
		return nil, tls.ConnectionState{}, err
	}
	return conn, conn.ConnectionState(), nil
}

// verifySPKIPin compares the leaf certificate's SPKI SHA-256 digest with the
// configured pin. The chain is already verified when this runs; a mismatch is
// still a failure, because the operator asked for a specific key.
func verifySPKIPin(state tls.ConnectionState, want []byte) error {
	if len(state.PeerCertificates) == 0 {
		return &dotFailure{kind: FailureCertificate, err: errors.New("DNS over TLS peer presented no certificate")}
	}
	got := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return &dotFailure{
			kind: FailurePinMismatch,
			err:  fmt.Errorf("leaf certificate SPKI SHA-256 mismatch: got %s", base64.StdEncoding.EncodeToString(got[:])),
		}
	}
	return nil
}

// classifyDoTFailure maps a failed DoT attempt to an error carrying its status
// kind. A consumed attempt budget is a timeout even when the socket also
// reported a closed connection, because the operator needs a blocked or stalled
// provider told apart from one that refused the handshake.
func classifyDoTFailure(attemptCtx context.Context, err error) error {
	if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
	}
	if isCertificateVerificationError(err) {
		return &dotFailure{kind: FailureCertificate, err: err}
	}
	return &dotFailure{kind: FailureTLSHandshake, err: err}
}

// isCertificateVerificationError reports whether err is a chain or name
// verification rejection rather than a protocol-level handshake failure.
func isCertificateVerificationError(err error) bool {
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &certificateInvalid) ||
		errors.As(err, &hostnameError)
}
