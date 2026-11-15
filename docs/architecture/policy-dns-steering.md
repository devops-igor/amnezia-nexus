# Policy DNS Steering & Plain-DNS Interception

Policy routing grants a direct egress path only when a client's own DNS answer
proves that a destination is not on the active policy list. This document
describes the two mechanisms that produce that evidence: steering generated
client configurations to the policy resolver, and intercepting plain DNS so
answers become routing observations.

## 1. Why both mechanisms exist

The policy resolver is a userspace DNS service (`internal/vpn/dns`) that answers
A queries, evaluates the answer against the active policy snapshot, and writes
client-scoped observations into the route cache. A destination is `Direct` only
when fresh, session-scoped evidence says so; missing, expired or foreign
evidence is `Unknown` and is proxied (fail-closed).

Evidence can only come from a query the resolver actually sees. Two independent
gaps make that impossible without this feature:

- A generated client configuration that lists external resolvers sends its DNS
  straight out, so the resolver observes nothing.
- A query addressed to an external resolver is not the gateway address, so the
  resolver's transport would not answer it even if it arrived.

Steering closes the first gap; interception closes the second.

## 2. Steering generated client configurations

`Service.clientConfigDNSServers` (`internal/vpn/client_config.go`) decides the
`DNS =` directive of every portal client configuration:

| Policy routing | Rendered `DNS =` |
| :--- | :--- |
| active, policy resolver present | the tunnel gateway address (subnet `.1`), one entry |
| inactive, or resolver not running | the existing external resolver defaults, unchanged |
| active but resolver missing | the existing external resolver defaults, unchanged |

The gateway address is pushed only when `PBREnabled()` is true **and** the PBR
configuration holds a live DNS gateway with a valid IPv4 gateway address. A
configuration is never pointed at a resolver that is not running.

`awg.RenderClientConfig` emits a single address when both DNS slots are equal.
Distinct resolvers keep their existing order and formatting, so inactive
configurations are byte-identical to the previous output.

### Already-downloaded configurations

A configuration downloaded while policy routing was active keeps the gateway
address after policy routing is disabled. Those clients continue to send plain
DNS to the tunnel gateway, but the policy resolver is not installed while
policy routing is inactive, so the queries follow the ordinary tunnel path
toward the backend and are answered there only if the backend serves DNS on the
tunnel gateway address. In practice the client must re-download its
configuration (or policy routing must be re-enabled) for DNS to be answered by
the policy resolver again. Steering only affects newly generated
configurations; it never rewrites a file a client already holds.

## 3. Plain-DNS interception

Interception exists only while policy routing is active. `Forwarder.SetPBREnabled`
selects between the legacy and the policy-routed path; the DNS handler is
installed by `ConfigurePBR` and removed by `TeardownPBR`. With policy routing
inactive, port-53 traffic keeps its previous routing and no handler exists.

### Where a packet is matched

`Forwarder.routeClientPBR` (`internal/vpn/forwarder/pumps.go`) submits every
IPv4 packet whose destination port is 53 to the DNS handler, regardless of
destination address, **after** the prohibited-destination guard has run:

1. Sticky-flow decisions still win first, exactly as for other traffic.
2. `ValidateDirectDestination` still drops loopback, link-local, RFC1918,
   CGNAT, multicast and metadata destinations. The designated gateway
   address on port 53 remains the one explicit exception. Interception never
   converts a prohibited destination into an answer or an egress path.
3. Non-TCP/UDP protocols still take the proxy fallback.
4. Port 53 on either TCP or UDP is submitted to the policy resolver.

`gatewaydns.Gateway.TrySubmit` then handles the packet. Queries addressed to
the gateway are unchanged. A foreign destination is handled only when the
gateway was built with `InterceptAllDestinations`, which production enables
exactly for the policy resolver installed while policy routing is active.

### UDP replies

`Gateway.handleUDP` already builds the reply from the packet's destination
address and port 53. For an intercepted foreign destination that is the queried
address, so the client sees a reply from the resolver it asked. No additional
translation state is needed.

### TCP replies

The gateway's netstack transport only terminates connections addressed to the
gateway. For a foreign TCP destination the gateway applies an address
translation (`internal/vpn/dns/gateway_nat.go`):

- **Outbound** (client to netstack): the destination address is rewritten to
  the gateway address and the IPv4 and TCP checksums are recomputed. The
  translation is recorded against the client flow's source address and port.
- **Inbound** (netstack to client): a reply whose source is the gateway
  address and port 53 is rewritten back to the address the client originally
  queried, with both checksums recomputed.

Translations are per session, bounded to 256 entries, and discarded after 60
seconds of idleness; a new translation for the same client flow replaces the
old one. Fragmented TCP packets cannot be translated safely and are dropped.
A flow that later targets the gateway address itself clears any translation it
recorded for an earlier foreign resolver, so a reply is only ever rewritten to
the address the client actually queried. The gateway address response and a
translated response are therefore indistinguishable to the client, and an
unmodified DNS client accepts both.

### Observations

Both paths converge on the same resolver call and the same observation code:
`Server.ServeDNSMessage` resolves the query, the UDP and TCP transports call
`ObserveResponseWithSessionID`, and `gatewaydns.ObserveResponse` classifies the
terminal A records against the active snapshot. A matched destination becomes
`Proxy`, an unmatched public destination becomes `Direct`, and the observation
expires at the minimum answer TTL capped by the server's maximum TTL. Evidence
is written into the authenticated session's cache scope, so it is bounded by
the session lifetime and never visible to another session.

## 4. Limitations

- **Encrypted DNS is out of scope.** DNS over HTTPS (443) and DNS over TLS
  (853) are not detected, intercepted or decrypted. Those destinations produce
  no evidence, remain `Unknown`, and are proxied. A client configured for
  encrypted DNS therefore gets no direct-path benefit from policy routing.
- **IPv4 only.** Interception and policy matching are IPv4. IPv6 DNS is not
  observed.
- **TTL-zero answers produce no evidence** for unmatched destinations, the
  existing conservative rule; matched destinations still record `Proxy`.
- **Prohibited destinations are not intercepted.** The existing
  prohibited-destination drop runs before interception and is not weakened.
