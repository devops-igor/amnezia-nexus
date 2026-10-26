// Package vless provides a pure-Go VLESS client dialer with REALITY TLS transport
// and active-probing resistant TLS handshake health probing for egress backends.
//
// # Build Tag Requirement
//
// This package and all REALITY functionality in the sing-box/sing-vmess ecosystem
// require the build tag "with_utls". If compiled without "-tags with_utls", compilation
// fails via tags_guard.go to prevent runtime panics or insecure fallback behavior.
//
// # Half-Close Constraints
//
// Connections returned by Dialer.DialContext do not support TCP half-close (CloseWrite).
// Upstream VLESS framing does not propagate TCP half-close FIN packets. Downstream
// consumers such as streambridge must rely on idle read timeouts or connection reap timers
// rather than half-close signaling.
//
// # Security and Health Probing Limits
//
// The REALITY handshake prober (probeVLESSReality) authenticates the server's public key,
// short ID, and camouflage TLS identity without transmitting any VLESS payload bytes.
// This preserves active probing resistance against censorship detection.
// As a consequence of transferring zero payload, client UUID authentication is not
// evaluated during handshake probing; invalid UUIDs will connect successfully at the TLS
// layer but will fail or time out on data transfer.
//
// Sensitive credentials including UUIDs, private keys, and short IDs must never be logged
// or exposed above debug level.
package vless
