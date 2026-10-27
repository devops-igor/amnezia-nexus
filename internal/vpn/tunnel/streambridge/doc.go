// Package streambridge implements a userspace netstack stream bridge adhering to
// forwarder.PacketDevice and vpn.BackendDevice.
//
// It terminates client TCP and UDP flows in a private in-memory gVisor netstack
// and splices them onto an outbound StreamDialer (such as sing-box VLESS+REALITY
// or NaiveProxy egress tunnels). This architecture enables userspace stream proxy
// egress without requiring root privileges, kernel TUN devices, or kernel-level routing.
//
// Zero-Copy Boundary:
// The zero-copy invariant established in Epic #384 and #394 for AmneziaWG data-path
// components (AWGClientDevice and VirtualTUN) does not apply to this stream bridge.
// Because stream proxies operate at L4/L7 rather than L3 packet forwarding, payload
// copying into netstack packet buffers and outbound sockets is unavoidable. The stream
// bridge maintains its own strictly bounded memory budget using sync.Pool buffer pools
// (32 KiB for TCP, 64 KiB for UDP) and constrained netstack TCP buffer ranges (64 KiB
// default per direction).
//
// Protocol Constraints:
//   - IPv4 Only: Stream proxy backends only handle IPv4 packets in this phase.
//     Non-IPv4 packets injected via Write are dropped and counted as dropped packets.
//   - No ICMP: Stream proxy protocols (VLESS, NaiveProxy) cannot tunnel ICMP packets.
//     Ping through a stream bridge backend will time out by design; health probing is
//     handled via protocol-native mechanisms.
//   - Client MSS: Netstack automatically advertises an MSS derived from the configured
//     MTU (e.g., MSS 1240 for MTU 1280), preventing packet fragmentation.
//   - Source Address: The remote proxy server observes its own egress IP, not the
//     client's private IP.
package streambridge
