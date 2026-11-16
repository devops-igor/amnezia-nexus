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
    {"address": "dns.example.com", "port": 5353, "transport": "plain"}
  ]
}
```

Rules (`policy.Upstream.Validate`, applied by `policy.Settings.Validate`):

| Rule | Rejection |
| :--- | :--- |
| at most three entries | the list exceeds the maximum |
| explicit port 1-65535 | a missing port or one outside the range |
| IPv4 literal, IPv6 literal or hostname | malformed literal or hostname (lengths, labels, characters) |
| never loopback, multicast or unspecified | the address falls in that class (`localhost` included) |
| no duplicate entry | the same transport and host:port appears twice |
| a known transport | an unknown transport name, or a transport this build does not implement |

Validation is pure and runs before persistence, so a rejected request returns a
specific error and writes nothing; the previously stored record stays in effect.
An absent or empty list means "use the effective defaults", which is what keeps a
record written before this field existed working unchanged.

The transport field is part of the contract from the start. Only `plain` (UDP
with TCP fallback on truncation) is implemented; `dot` and `doh` are rejected
with a specific error instead of being accepted and carried in clear text. An
entry never silently downgrades, and the resolver refuses a non-plain entry at
construction and at exchange time as well, so the rule holds even for a caller
that bypasses settings validation.

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
| `last_upstream_failure_kind` | `timeout`, `network`, `servfail`, `invalid_response`, and later `tls_handshake`, `certificate`, `http_status` |

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

## 5. Explaining a decision (dry run)

`POST /api/vpn/policy/explain` answers the ordinary operational question "would
this destination go direct or through the proxy, and why?" for one name or
address, without sending client traffic. It is admin-only and carries the same
CSRF requirement as the other policy endpoints because it is mounted in the same
`/api/vpn/policy` group.

### Request and answer

The body carries `domain`, or `ip`/`ips` (at most eight addresses), and an
optional `session_id`. Supplying addresses skips the lookup entirely, so a
destination can be evaluated with no DNS traffic at all. The answer reports:

| Field | Meaning |
| :--- | :--- |
| `decision` | the CURRENT action for the evaluated addresses: `DIRECT`, `PROXY`, `DROP` or `UNKNOWN` |
| `reason` | one machine-readable cause of that action: `policy_disabled`, `prohibited_destination`, `cidr_rule`, `cached_proxy_evidence`, `fresh_evidence_direct`, `expired_evidence`, `evicted_evidence`, `stale_evidence_generation`, `no_trusted_evidence`, `no_usable_address`, `name_unresolved`, `no_policy_snapshot` |
| `prospective` | the rule classification of the submitted name, reported separately: `matched`, `decision` (`PROXY`), `reason` (`domain_rule` or `cname_rule`), `matched_name`, `requires_observed_answer` and the `rule` |
| `rule` (inside `prospective`) | the matched rule: its base name, its shape (`apex`, `apex_and_subdomains`, `subdomains`) and the lists that contributed the base entry (`contributors`, with `source_kind` `preset`/`custom`/`mixed`) |
| `prefix` | the most specific matching CIDR prefix and the lists that supplied exactly that prefix |
| `addresses` | one current-action verdict per evaluated address, with its own decision, cause, prefix and evidence |
| `evidence` | the session evidence the decisive verdict rests on: `state`, `decision`, `generation`, `expires_in_seconds` and the elapsed age (`age_seconds` or `age_unavailable_reason`), described below |
| `evaluated_at` | the instant the evidence was evaluated at, sampled *after* the optional blocking lookup |
| `resolution` | how the name was resolved: `configured_resolver`, `caller_supplied`, `not_attempted` or `unavailable`, the upstreams dialled, the deadline, the CNAME chain and the answer, or the resolver's error |
| `limitations` | the caveats that apply, as tokens |

### Evidence age

`expires_in_seconds` and `age_seconds` are different quantities. Neither is
computed from the other.

- `expires_in_seconds` is the remaining lifetime: the stored deadline minus
  `evaluated_at`. It is negative once the evidence has expired. Its meaning is
  unchanged.
- `age_seconds` is the elapsed time, in whole seconds, from the instant the
  observation was recorded to `evaluated_at`. The route cache stores that
  instant with each entry: the receive time of the DNS response on the gateway
  path, and the time of the call on the in-memory cache's own observe path. It is never derived from the deadline or from a TTL: the cache
  does not know the TTL an answer carried, and two entries can have the same
  remaining lifetime and different ages.
- An entry holds one observation. When a later observation replaces or extends
  it, the entry takes that observation's instant together with its decision and
  deadline. When the earlier observation is kept (a repeat that expires sooner,
  or a DIRECT answer that must not displace PROXY), its instant is kept too.

`age_seconds` is present only for fresh evidence with a recorded instant, and a
just-observed entry reports `0`. In every other case it is omitted and
`age_unavailable_reason` names the cause:

| `age_unavailable_reason` | Meaning |
| :--- | :--- |
| `no_evidence` | the session holds nothing for this address |
| `evidence_not_fresh` | the evidence is expired, quarantined, from an earlier policy generation or retired. The data path ignores it, so an age would describe evidence that does not apply |
| `observation_instant_not_recorded` | fresh evidence is stored without an observation instant. The answer also carries the `evidence_age_not_recorded` limitation |

No `evidence` object, and so no age, is returned when no session is selected,
when the selected session owns no cache scope, or when policy routing is
disabled. `limitations` already says which of those applies
(`evidence_requires_a_selected_session`, `session_has_no_cached_evidence`).

Records written without an instant are never given one. The route cache is
in memory only and is rebuilt on restart, so within a running panel every entry
is written by code that records the instant and the
`observation_instant_not_recorded` case is a guard for a record that lacks one.
Such a record reports no age rather than zero, a TTL-derived number or the time
of the explain request.

The current action follows the packet path exactly, because the packet path
never looks at a name: prohibited destination (`DROP`), snapshot CIDR
(`PROXY`), the session's cached `PROXY` decision (`PROXY`), its cached `DIRECT`
decision (`DIRECT`), then the safe default `PROXY`. A matched domain rule is a
real policy fact but not a route: it is reported under `prospective`, which
becomes the destination's action only once the client's own answer for that
name is observed. A name that resolves to several addresses is summarised twice
over: every address is reported on its own, and the headline is the unanimous
verdict when they agree (`summary: "unanimous"`) or the most restrictive one when
they disagree (`summary: "most_restrictive"`, ordered `DROP` > `PROXY` >
`UNKNOWN` > `DIRECT`), so a name is never reported as safer than its worst
address. With no evaluable address there is no action: the answer is `UNKNOWN`
with `name_unresolved` or `no_usable_address`, and a matching rule is still
reported as prospective.

### Read-only by construction

The endpoint never publishes a matcher, writes a route-cache entry, records an
observation, syncs a list, refreshes anything or moves a counter:

- the route cache is read through `RouteCache.Get`/`SessionScope`, which never
  create a scope, and through `SessionCache.Inspect`, which loads the current
  view once and reads one entry without publishing a view, pruning an expired
  entry or extending a deadline;
- evidence is written only by `gatewaydns.ObserveResponse` through the DNS
  handler, which this path never calls: the ad-hoc answer is classified locally
  and discarded, so it is explicitly excluded from the evidence path;
- interception exists only on the packet path, and no packet, flow or counter
  path is entered;
- the lookup is bounded by an explicit timeout (2 s by default, 5 s for the whole
  request) and is an ordinary query sent out to the configured upstreams. That
  query does leave the panel: a name submitted without addresses is resolved
  through the configured resolver, and the answer reports `resolution.method` so
  the operator can see it. Client traffic, routing evidence and dataplane
  counters stay untouched;
- the lookup uses the resolver's read-only exchange entry point
  (`UpstreamResolver.ExchangeReadOnly`), which runs the identical budget,
  failover and TCP-fallback path but does not publish the attempt to the live
  resolver's health status. Without that, one dry run could clear a recorded
  upstream failure or invent one, changing the operator-facing status that #824
  reports. A test drives a real resolver: after a genuine recorded failure, a
  successful dry run leaves the status untouched and a failing dry run adds
  nothing;
- the DNS answer is classified by the observation path's own
  `gatewaydns.ClassifyAnswer`, not by a second traversal. Answers the observation
  path would discard — a CNAME cycle, ambiguous CNAMEs for one name, a name with
  both CNAME and A records, an unnormalizable intermediate or a truncated reply —
  are reported as unusable instead of being explained from. A parity table drives
  the explainer, the classifier and `ObserveResponse` over the same crafted
  answers and requires all three to agree.

A test asserts the entry count, the session count, the stored evidence and the
dispatcher counters are identical before and after an explanation, and that an
address which only matched a CIDR rule gained no evidence. A second test drives
the real forwarder and asserts that the explained action equals what
`RouteClientToBackend` actually does for the same fresh flow. A third asserts the
live resolver's status is unchanged by a dry run.

### What the policy section shows

The section's one line shows the current action and its cause for what the
operator typed. A second line beneath it shows the rule that matched, with its
shape and the lists that contributed the base entry, or the CIDR range that
decided the action with its source. The rule line is labelled prospective and
says that it applies only after the client's own DNS answer is observed; the
current-action line is never derived from a submitted name. No match renders no
line rather than an empty one.

### Attribution

A compiled snapshot records which sources contributed each rule, packed into
spare bits of the per-rule byte, so naming the list costs no second index.
Domain provenance is recorded per BASE ENTRY, and a base entry merges the shapes
its sources supplied: a list that supplies only `*.shared.example` also appears
in the contributors of a queried `shared.example` apex, which it cannot match.
The field is therefore named `contributors` and documented as a base-entry
contributor list, not a proven supplier of the matched shape; splitting it per
shape would need a second per-rule index, which this change deliberately does
not add. CIDR provenance is exact, because a source either supplied that prefix
or did not.

A snapshot compiled from a durable last-known-good generation stores merged
rules only: the rule and its shape are still reported, the contributor list is
empty rather than invented. The same holds when a snapshot has more sources than
the encoding holds.

## 6. Limitations

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
