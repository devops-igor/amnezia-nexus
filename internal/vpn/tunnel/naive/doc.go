// Package naive implements a pure-Go NaiveProxy client dialer over HTTP/2 and
// HTTP/3 (QUIC) and an authenticated CONNECT health prober.
//
// NaiveProxy uses Chromium-compatible network stacks to evade censorship by
// funneling traffic through standard HTTP CONNECT proxies (such as Caddy with
// the forwardproxy plugin). This package provides a pure-Go implementation of
// the NaiveProxy client dialer without native CGO or cronet dependencies,
// preserving CGO_ENABLED=0 static compilation across all supported platforms.
//
// # Protocol Framing
//
// Traffic is established via standard HTTP CONNECT tunneling over TLS:
//   - HTTP/2 (RFC 7540): Multiplexed streams over a TLS TCP transport.
//   - HTTP/3 (RFC 9114): Multiplexed streams over a QUIC UDP transport.
//   - Proxy Authentication (RFC 7617): HTTP Basic authentication transmitted
//     on the "Proxy-Authorization" header.
//
// # Transport Scope & Limitations
//
// NaiveProxy exclusively tunnels TCP streams. UDP-CONNECT / MASQUE datagram
// extensions are not supported by standard NaiveProxy server implementations.
// Consequently, Dialer.DialContext rejects any network request other than "tcp".
//
// # Anti-Censorship & Security Standards
//
//   - Active Probe Resistance: Camouflage servers return HTTP 307/308 redirects
//     or decoy HTML pages for unauthenticated requests. The health prober
//     strictly rejects any non-200 status (including 307/308 and 407).
//   - Zero Fingerprinting: Dialers and probers omit custom User-Agent headers
//     to blend in with standard browser traffic.
//   - Lightweight Probing: Health checks issue an authenticated CONNECT to the
//     server's declared camouflage domain (Domain:443) and close immediately
//     upon receiving 200 OK without transmitting any tunneled payload bytes.
package naive
