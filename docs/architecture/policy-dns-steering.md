# Policy DNS Steering & Plain-DNS Interception

Policy routing grants a direct egress path from client DNS evidence, or from the
destination address itself when the client's DNS is invisible to the panel. This
document describes the mechanisms that produce that evidence — steering generated
client configurations to the policy resolver and intercepting plain DNS so
answers become routing observations — and, in section 6, the routing contract
that also classifies a destination by its address.

## 1. Why both mechanisms exist

The policy resolver is a userspace DNS service (`internal/vpn/dns`) that answers
A queries, evaluates the answer against the active policy snapshot, and writes
client-scoped observations into the route cache. A destination observed by that
resolver is `Direct` only when fresh, session-scoped evidence says so; missing,
expired or foreign evidence is `Unknown` and, until section 6 was implemented,
was proxied (fail-closed). A destination the panel never observed can now be
routed direct by address classification alone (section 6).

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
- It resolves through the effective default upstream pair
  (`policy.DefaultUpstreams()`: AdGuard `94.140.14.14` then `94.140.15.15`), the
  same one definition the resolver and the rendered client configuration derive
  from, so an issued profile does not change provider when the feature is
  disabled and the two cannot drift apart.

A transient failure to deliver one reply can retire the resolver authority of a
session. For a session that is still live, the next query replaces that retired
authority with fresh authority and closes the retired transport; a session that
has actually retired is never revived. Recovery therefore does not depend on a
reconnect or a new configuration download.

Newly generated configurations while policy routing is inactive keep the legacy
external defaults, as before. Steering never rewrites a file a client already
holds.

## 3. Upstream resolver configuration

The policy resolver's upstream list is operator configuration, stored in the
existing policy settings record under `upstream_dns` (issue #824). It is not a
new table, endpoint or service.

```json
{
  "enabled": true,
  "preset": "geoblock",
  "sync_interval_seconds": 3600,
  "upstream_dns": [
    {"address": "94.140.14.14", "port": 53},
    {"address": "2001:4860:4860::8888", "port": 53},
    {"address": "dns.example.com", "port": 853, "transport": "dot", "spki_pin": "ddJh1F65OO52y6H1L2TUCzCELTOlWg2Os3GV1RCi2iY="}
  ]
}
```

Rules (`policy.Upstream.Validate`, applied by `policy.Settings.Validate`):

| Rule | Rejection |
| :--- | :--- |
| at most three entries | the list exceeds the maximum |
| explicit port 1-65535, except the DoT default | a missing port on a plain entry, or one outside the range |
| IPv4 literal, IPv6 literal or hostname | malformed literal or hostname (lengths, labels, characters) |
| never loopback, multicast or unspecified | the address falls in that class (`localhost` included) |
| no duplicate entry | the same transport and host:port appears twice |
| a known, implemented transport | an unknown transport name, or a transport this build does not implement |
| an SPKI pin only on DoT, standard base64 of a 32-byte digest | a pin on a plaintext entry, or one that does not decode to a digest |

Validation is pure and runs before persistence, so a rejected request returns a
specific error and writes nothing; the previously stored record stays in effect.
An absent or empty list means "use the effective defaults", which is what keeps a
record written before this field existed working unchanged.

The transport field is part of the contract from the start. `plain` (UDP with TCP
fallback on truncation) and `dot` (DNS over TLS, RFC 7858) are implemented; `doh`
is rejected with a specific "not supported in this build" error instead of being
accepted and carried in another transport. An entry never silently downgrades,
and the resolver refuses an unimplemented transport at construction and at
exchange time as well, so the rule holds even for a caller that bypasses settings
validation.

### DNS over TLS

A `dot` entry is dialled as TLS to its own address and port (853 when the entry
states none, which normalization also writes into the record). The certificate
chain is verified against the system trust store, and the name that is verified
is the entry's address: a hostname entry sends SNI and is checked as a DNS name,
an IP-literal entry is checked against an IP SAN (and sends no SNI, as RFC 6066
requires). Verification is never skipped.

`spki_pin` is optional and pins the leaf key rather than the chain: standard
base64 (RFC 4648 section 4, with padding) of the SHA-256 digest of the leaf
certificate's `SubjectPublicKeyInfo`. A configured pin that does not match the
presented leaf fails the exchange even when the chain is valid, which keeps a
resolver reachable for the operator's key rather than for any key the trusted CA
issues.

The handshake and the exchange share the existing per-attempt budget, so a peer
that accepts TCP and stalls is reported as a timeout rather than consuming the
whole query deadline. A DoT entry sends no plaintext DNS: the transport dispatch
has no cross-transport fallback, failure moves only to the next configured entry,
and each entry keeps its own transport.

### One current list for every consumer

`Service.dnsUpstreams` (guarded by `Service.mu`) is the single owned list of
accepted upstreams. It is written only by the two paths that can accept one:
activation (`ConfigurePBR`, from the resolver that was actually installed) and
an accepted live change or disable (`ApplyEffectiveUpstreams`). Every consumer
reads it:

| Consumer | When it reads the list |
| :--- | :--- |
| policy resolver | installed at activation, swapped in place on an accepted change |
| continuity responder | rebuilt at teardown, at every install, and on an accepted change while policy routing is off |
| disabled startup | `startPersistedPolicyRouting` applies the persisted list even though the record is disabled |

A teardown therefore cannot rebuild the responder from the list the activation
started with: a list the operator replaced is never observable again, and a
disabled restart re-applies the saved list instead of falling back to the
defaults.

### Who owns the DNS path

Exactly one handler owns the forwarder's DNS path at a time:

| State | Installed handler | Installed by |
| :--- | :--- | :--- |
| policy routing active | policy resolver (`pbrDNSHandler`), with the matcher and the route observer | `ConfigurePBR` |
| policy routing inactive | continuity responder, no matcher and no observer | `TeardownPBR`, `ConfigurePBR`'s disabled/refused branches, and the disabled-startup install |

The idempotent install that runs at service start
(`installDNSContinuity`) defers while policy routing is active: a restart with an
enabled record activates policy routing before the data plane starts, and
replacing that handler would leave the status reporting policy routing enabled
while DNS produced no routing evidence. Disable transitions install the
responder explicitly, in their own order, so an issued gateway-DNS profile still
resolves after policy routing is turned off and a repeated install still keeps
its handler (no query in flight is dropped).

### Saves that omit the field

The existing policy form posts only `enabled`, `preset`, `custom_urls` and
`sync_interval_seconds`. An omitted `upstream_dns` therefore preserves the
stored list; an explicitly empty list (`"upstream_dns": []`) is the deliberate
reset to the effective defaults. The merge happens inside the serialized
settings mutation and the effective record is validated before it is written, so
a rejected merge writes nothing.

### Single source of truth

`policy.DefaultUpstreams()` is the one definition of the default pair. Both
consumers derive from it:

- the resolver's effective list (`policy.Settings.EffectiveUpstreams()`, which
  `initPBR` and a live settings update install on the running resolver);
- the `DNS =` pair a generated client configuration pushes when the policy
  gateway is not the answer path (`defaultClientDNSServers` in
  `internal/vpn/client_config.go`).

### Preserved budgets

The configured list changes which provider is dialled, not how. The overall
query deadline, the per-attempt deadline, the single alternate retry, TCP
fallback on truncation and SERVFAIL failover are unchanged. A transport failure
is an error, never a valid empty answer, and the server maps it to SERVFAIL for
the client.

### Status

`vpn.PolicyStatus` gains three fields, reported through the existing policy
status response (no new endpoint):

| Field | Meaning |
| :--- | :--- |
| `last_upstream` | the upstream that served the most recent accepted answer |
| `last_upstream_failure` | the upstream of the most recent failed attempt |
| `last_upstream_failure_kind` | `timeout`, `network`, `servfail`, `invalid_response`, `tls_handshake`, `certificate`, `pin_mismatch` (`http_status` is reserved for the DoH transport) |

A successful exchange clears the failure fields, so a working provider is never
reported as failing. A blocked provider now surfaces as a failure kind instead of
presenting as "no evidence yet". The fields carry resolver addresses only: no
queried names and no client data.

## 4. Plain-DNS interception

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
overwrites or clears a live sibling translation.

A translation is only a mapping. Removing one does not terminate the TCP
connection the netstack still holds, and that connection can emit a reply on its
port at any later time, however long the translation has been gone. An internal
port is therefore issued once per session and never returned to the pool, so no
later tuple can inherit a port that an older connection may still use. A reply
whose internal port holds no live translation is dropped rather than delivered
unchanged, because the packet carries nothing that could prove which tuple owns
it. When a session has issued all of its identities (the ports from 20000 to
65535, 45536 in total), a new intercepted TCP connection is refused and its
packets are dropped instead of being translated onto an identity that might
collide; the table still holds at most 256 translations. Fragmented or malformed
packets are dropped rather than translated. Replies therefore always appear from
the resolver the client queried, and an unmodified DNS client accepts them.

### Observations

Both paths converge on the same resolver call and the same observation code:
`Server.ServeDNSMessage` resolves the query, the UDP and TCP transports call
`ObserveResponseWithSessionID`, and `gatewaydns.ObserveResponse` classifies the
terminal A records against the active snapshot. A matched destination becomes
`Proxy`, an unmatched public destination becomes `Direct`, and the observation
expires at the minimum answer TTL capped by the server's maximum TTL. Evidence
is written into the authenticated session's cache scope, so it is bounded by
the session lifetime and never visible to another session.

## 5. Aggregate source, local entries and the never-proxy guard

The `aggregate` preset unions the reviewed 24-list manifest in
`internal/policy/aggregate.go`: six `Categories/` lists, sixteen `Services/`
lists, `Russia/inside-raw.lst` and `Ukraine/inside-raw.lst`. The manifest is
explicit and reviewable; converted transport variants, `src/` derivatives and
`Russia/outside-raw.lst` are not fetched.

Every component is fetched with the existing HTTPS/SSRF, conditional-request,
size, timeout and rule-count protections. A component failure keeps the previous
published policy and reports the failed component; a first activation with an
incomplete aggregate is refused rather than publishing partial coverage.
Duplicate rules collapse into one rule with every contributing source attributed
within the snapshot provenance budget, and per-component status reports accepted,
excluded, duplicate and failure counts.

The never-proxy guard is applied to every external component and to local
entries, and again to the composed rule set. It removes DOMAIN rules that are
equal to, below, or broad ancestors of the built-in patterns and the
operator-supplied `excluded_domains` list. Excluded names keep the existing
default path; the guard never turns another destination DIRECT. Local entries are
persisted as an additive settings field, accept bare domains, `*.` subdomains,
IPv4 literals and IPv4 CIDRs, and are refused with the named guard reason when a
domain matches the guard or the exclusion list. An empty local list does not
change the generation; adding or removing a local entry does.

The built-in guard includes the Russian state/government patterns, the
internal-service denylist and the whole VK family (`vk.com`, `vk.ru`,
`vkontakte.ru`, `userapi.com`, `vk-apps.com`, `vkvideo.ru`, `vkforms.ru`,
`vkplay.live`, `vkopt.net`, `vk.me`, `vk-cdn.net`). `excluded_domains` is the
operator-editable half of the same set: bare domains and `*.` entries, persisted
with the policy settings and applied with the same ancestor semantics. IPv4,
IPv6 and CIDR entries are refused there because a name-based list cannot override
a proxy CIDR at the packet path.

**Ancestor-removal consequence.** A rule is removed when it is equal to, a
subdomain of, or an ancestor of a protected name. Excluding `api.example.com`
therefore also removes a proxied `example.com` rule, so the whole parent becomes
direct. That is the fail-safe direction: a broad parent rule would otherwise
proxy the excluded name. If a single subdomain must stay direct while its parent
remains proxied, that needs a decision-time DIRECT rule before the PROXY decision
and is not provided by this guard.

The guard is name-based, and that is the exact boundary of the guarantee:

- **Domain rules are protected.** The aggregate manifest contains only
  `FormatDomains` lists, and every guarded name is removed from every external
  component, from local domain entries and from the composed candidate. Six
  `Russia outside` names also arrive through other components; the guard removes
  those too.
- **CIDR rules are not rewritten.** The forwarder matches a CIDR against the
  packet's destination address before it consults DNS evidence or the address
  classifier (`forwarder.decideEgress`, row 2), so a CIDR an operator supplies is
  routed by address. A name-based guard cannot guarantee DIRECT for an address
  inside such a range, because it has no address-to-name mapping to test. Adding
  a CIDR is therefore an explicit choice to proxy that range; do not add one that
  covers a destination that must stay direct. The shipped aggregate has no
  CIDRs.
- **Stored snapshots are revalidated.** `PrimeBaseline`, `AdoptBaseline` and the
  vpn last-known-good fallback check a durable generation's domain rules against
  the current guard and operator exclusions before publishing them. A snapshot
  written before a guard pattern or exclusion existed is reported as a foreign
  baseline and is never activated; if the upstream fetch also fails, startup
  activation is refused rather than proxying the stale protected name.

## 6. Routing contract: DNS evidence and address classification

Both evidence sources feed one contract, implemented in one place:
`forwarder.decideEgress` (`internal/vpn/forwarder/routing_decision.go`). The rows
are applied in this order, and the branch that decided is recorded on the flow so
the diagnosis can name it.

| Condition | Result | Recorded reason |
| :--- | :--- | :--- |
| Invalid, prohibited or internal destination | DROP | `prohibited_destination` / `invalid_client_packet` in the DROP ledger |
| Explicit operator PROXY override (a published address rule) | PROXY | `proxy_cidr_rule` |
| *Migration row:* client DNS evidence for this destination | DIRECT / PROXY | `evidence_direct` / `proxy_cached_evidence` |
| Inside the Russian allocation **and** a known multi-region CDN | PROXY | `allocation_cdn_excluded` |
| Inside the Russian allocation, no CDN exclusion | DIRECT | `allocation_direct` |
| Unknown or uncovered destination | PROXY | `no_trusted_evidence` |
| Required egress unavailable for a DIRECT decision | DROP, no switch | `direct_egress_unavailable` in the DROP ledger |

The two DROP rows never leave through the other path: a prohibited destination is
refused before any routing input is consulted, and a DIRECT decision whose egress
is unavailable is recorded as a DROP with the producer's reason rather than being
re-decided as PROXY.

**The evidence row is temporary.** While the DNS evidence subsystem exists, its
verdict sits between the explicit override and the address classifier, in exactly
one block marked `MIGRATION ROW — TEMPORARY` in `decideEgress` and one field
(`migrationEvidence`) on its input. Removing that block yields the table above
without the evidence row and changes no other row; a test asserts that rows one
and two decide identically with or without evidence.

### Why two inputs

| Question | Answered by | Why the other input cannot answer it |
| :--- | :--- | :--- |
| Is the address inside the Russian allocation? | The committed inventory (`internal/policy/inventory`), RIR delegation | The embedded ASN table reports the origin network's registration: Yandex prefixes are originated by AS208398, a Serbian-registered network, so every Yandex address reads `RS` while RIPE records the space as RU |
| Does the range belong to a multi-region CDN? | The embedded ASN table (`internal/geodb`), `KnownCDNASNs` | An allocation zone carries no ASN, so an Amazon or Cloudflare range inside the Russian allocation would be routed direct |

`policy.AddressClassifier` joins both and answers only those two questions. It is
installed by `ConfigurePBR` and removed when policy routing is disabled or torn
down.

**With no classifier installed, the contract keeps its previous decision path,
not a new one.** The migration row still routes on fresh client DNS evidence
(`evidence_direct` for a retained `Direct`, `proxy_cached_evidence` for a retained
`Proxy`), and a destination with no usable evidence keeps the fail-safe `PROXY`
default. An absent classifier therefore does not mean "every destination is
proxied": a destination the client's own retained DNS evidence resolved direct is
still routed direct, exactly as it was before this input existed, and only the
address-only decisions disappear. That distinction matters when reading the
diagnosis, because the reason token on a direct flow names which of the two paths
decided it.

### The operator inventory override

The committed allocation set is the baseline, and an operator can correct or
extend it without waiting for a release. The override is stored in the same
policy settings record as the other policy fields:

- it is the `inventory_override` list on `PUT /api/vpn/policy` and on the policy
  settings section, one IPv4 prefix per line (the same line shape as a custom
  source, so an operator does not learn a second syntax);
- it is validated where it is written. A body that is not a prefix list, a
  mistyped address such as `203.0.113.999`, an IPv6-only body, or a body with no
  prefix at all is refused with `400` and the stored record is left exactly as it
  was, so a typo can never be persisted as an override that applies nothing;
- it takes precedence over the shipped set for every address it contains, and an
  address it does not name keeps the committed answer. It answers set membership
  only: an explicit PROXY rule and the prohibited/internal guard still outrank it,
  so an override naming a private range cannot route such a destination;
- it is applied on activation and on an accepted save while policy routing is
  live. The classifier is replaced rather than the data path rebuilt, so a save
  that only changes the override does not interrupt live flows;
- the policy status reports it beside the shipped set — the shipped prefix count,
  source, retrieval date and digest stay the shipped set's own facts, and the
  override's count and digest are reported as the override. An override is
  therefore never presented as part of the committed artifact.

### What classification does not mean

- **Allocation is not hosting location.** Membership is an approximation from RIR
  delegation. The reason token says `allocation_direct`, never "hosted in Russia".
- **A direct path still egresses through this host's WAN address.** If that
  ingress sits outside Russia, a Russian service that refuses foreign source
  addresses still fails. That is why the per-flow record separates *routed direct
  and written to WAN* from *routed direct and failed*: the second is the signal
  that the egress location, not the classifier, is the problem.
- **A successful WAN write is not proof that the application worked.** The write
  records that the packet left through this host's WAN interface; it says nothing
  about what the remote service did with it, and nothing about whether a reply
  came back. The return direction is a separate observation, `not_observed` when
  no reply was seen, so a direct flow can read as written and still have served
  nothing.
- **The CDN list is conservative.** `KnownCDNASNs` covers Cloudflare, Fastly,
  Akamai, Amazon, Google and Microsoft. It is an exclusion list, not
  comprehensive CDN detection; a Russian service behind an unlisted CDN is routed
  direct, and a listed CDN range inside the allocation stays proxied.
- **Prohibited destinations are refused first.** The prohibited check is
  address-side (`ValidateDirectDestination`) and is the contract's first row, so
  an operator DIRECT input — including an operator inventory override that names
  a private or internal range — cannot route such a destination.

## 7. Limitations

- **Encrypted DNS is not observed.** DNS over HTTPS (443) and DNS over TLS
  (853) are not detected, intercepted or decrypted, so those queries produce no
  evidence. Their destinations are routed by the address classifier of section 6
  when it can classify them, and proxied otherwise. A downstream destination
  inside the Russian allocation therefore reaches a direct path even for a
  client configured for encrypted DNS, while everything else keeps the proxy
  default.
- **IPv4 only.** Interception and policy matching are IPv4. IPv6 DNS is not
  observed, and an operator inventory override is validated as an IPv4 prefix
  list, so an IPv6-only body is refused rather than stored as an override that
  would apply nothing.
- **TTL-zero answers produce no evidence** for unmatched destinations, the
  existing conservative rule; matched destinations still record `Proxy`.
- **Continuity answers are not evidence.** While policy routing is inactive the
  gateway-address responder answers DNS but records no observation, so issued
  profiles resolve and continue to proxy until policy routing is enabled again.
- **Encrypted upstream transports are not implemented yet.** The persisted
  configuration already selects a transport per entry, and an entry configured
  for DoT or DoH is rejected rather than carried in plaintext. Until those
  transports land, policy routing resolves over plain DNS to the configured
  list.
- **Operator-configured upstreams drive the resolver only.** A generated client
  configuration keeps naming the gateway while policy routing is active and the
  effective default pair while it is inactive; it is never pointed at an
  operator-supplied upstream, which may be reachable from the host but not from
  the client's own egress.
- **Prohibited destinations are not intercepted.** The existing
  prohibited-destination drop runs before interception and is not weakened.
