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

### Issued configurations after disablement

A configuration downloaded while policy routing was active keeps the gateway
address after policy routing is disabled, and that address keeps answering. The
gateway-address-only continuity responder
(`internal/vpn/vpn_dns_continuity.go`) serves it over UDP and TCP for as long as
the panel runs, independent of the policy classifier. `TeardownPBR`, a refused
activation, and service start with policy routing disabled all install it as the
forwarder's DNS handler.

The continuity responder is deliberately not a second policy resolver:

- It answers only queries addressed to the gateway DNS address. External port 53
  is not intercepted while policy routing is inactive.
- It is constructed without a policy source and without a route observer, so its
  answers create no routing observation and can never grant `Direct`. An issued
  profile keeps resolving while disabled and stays fail-closed for routing.
- It resolves through the same upstream pair as the policy resolver (AdGuard
  `94.140.14.14` then `94.140.15.15`), so an issued profile does not change
  provider when the feature is disabled.

Newly generated configurations while policy routing is inactive keep the legacy
external defaults, as before. Steering never rewrites a file a client already
holds.

## 3. Plain-DNS interception

Interception of arbitrary port-53 destinations exists only while policy routing
is active. `Forwarder.SetPBREnabled` selects between the legacy and the
policy-routed path. `ConfigurePBR` installs the all-destination policy handler;
`TeardownPBR` replaces it with the gateway-address-only continuity responder
described above, which does not intercept external port 53 and records no
evidence. With policy routing inactive the legacy path consults that responder
only for the designated gateway address on port 53; every other packet keeps its
previous routing.

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

While policy routing is inactive, `Forwarder.routeClientToBackend` admits one
narrow class to the continuity responder through `handleLegacyGatewayDNS`: an
IPv4 UDP or TCP packet that the strict ingress parser accepts and that is
addressed to the designated gateway address on port 53. Anything else —
including every external port-53 destination — continues down the unchanged
legacy route.

`gatewaydns.Gateway.TrySubmit` then handles the packet. Queries addressed to
the gateway are unchanged. A foreign destination is handled only when the
gateway was built with `InterceptAllDestinations`, which production enables
exactly for the policy resolver installed while policy routing is active; the
continuity responder is built without it.

### UDP replies

`Gateway.handleUDP` already builds the reply from the packet's destination
address and port 53. For an intercepted foreign destination that is the queried
address, so the client sees a reply from the resolver it asked. No additional
translation state is needed.

### TCP replies

The gateway's netstack terminates TCP connections on the gateway address and
identifies each connection by its local and remote endpoints. Two client
connections may legally share the client address and port while addressing
different resolvers, so a destination-only rewrite would collapse them onto one
internal connection. Every intercepted TCP DNS connection therefore receives its
own internal source port from a small bounded range
(`internal/vpn/dns/gateway_nat.go`):

- **Outbound** (client to netstack): the original client/resolver tuple is keyed,
  an internal port is allocated when the tuple is new, and the packet is
  rewritten to `client:internal-port -> gateway:53` with the IPv4 and TCP
  checksums recomputed.
- **Inbound** (netstack to client): the internal port identifies the exact
  original tuple and the reply is rewritten back to
  `resolver:53 -> client:original-port`, with both checksums recomputed.

A later packet of the same connection reuses its internal identity. Entries are
per session, capped at 256, discarded after 60 seconds of idleness, and evicted
oldest-first only when the cap is reached; another connection's mapping never
overwrites or clears a live sibling translation. Fragmented or malformed packets
are dropped rather than translated. Replies therefore always appear from the
resolver the client queried, and an unmodified DNS client accepts them.

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
- **Continuity answers are not evidence.** While policy routing is inactive the
  gateway-address responder answers DNS but records no observation, so issued
  profiles resolve and continue to proxy until policy routing is enabled again.
- **Prohibited destinations are not intercepted.** The existing
  prohibited-destination drop runs before interception and is not weakened.
