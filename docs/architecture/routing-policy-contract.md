# Routing Policy Contract: Destination Address Classification

Policy routing decides between two egress paths — the proxy backend the client
session already uses, and a direct path out of this host's own WAN interface —
**from the destination address alone**. This document is the contract that
decision follows: which input is authoritative, which row of the precedence table
wins, what has to be installed before activation means anything, what the operator
may override, and what the answer deliberately does not claim.

The specification lives in one side-effect-free function,
`forwarder.decideEgress` (`internal/vpn/forwarder/routing_decision.go`). The
packet path reads its inputs once and calls it; nothing else re-decides a packet.

## 1. Authority

The **address classifier** is the routing authority. Everything a destination
resolves to without an explicit operator rule comes from it:

| Question | Answered by | Symbol |
| :--- | :--- | :--- |
| Is this address inside the Russian allocation? | the committed allocation inventory, built from RIR delegation (`internal/policy/inventory`) | `policy.Inventory.Match` |
| Does the covering range belong to a known multi-region CDN? | the embedded ASN table (`internal/geodb`, `ip2asn.bin.gz`) | `geodb.KnownCDNASNs`, `geodb.IsMultiRegionCDNASN` |

`policy.AddressClassifier` joins both and answers those two questions only
(`policy/classify.go`). It holds no mutable state, takes no locks and performs no
I/O, so it is shared between packet paths without synchronisation.

On top of the classifier the record carries exactly two operator inputs: an IPv4
PROXY exception list, which forces matching addresses onto the proxy *ahead* of
the classifier, and an inventory override, which corrects the allocation set for
the addresses it names (§5).

**Domains are not a routing input.** Nothing in the packet path maps a name to a
decision: the exception list is refused at the settings boundary when a line is
not an IPv4 prefix (`policy.ErrLocalRuleNotPrefix`), and the inventory override
refuses a body that carries no prefix at all (`policy.ErrInventoryNotPrefixList`).

## 2. Precedence

Applied in this order. The branch that decided is recorded on the flow, so the
client diagnosis names the row instead of inviting a reader to infer it.

| # | Condition | Result | Recorded reason |
| :--- | :--- | :--- | :--- |
| 1 | invalid, prohibited or internal destination | DROP | `prohibited_destination` / `invalid_client_packet` in the drop ledger |
| 2 | explicit operator PROXY override (a published address rule) | PROXY | `proxy_cidr_rule` |
| 3 | inside the Russian allocation **and** a known multi-region CDN | PROXY | `allocation_cdn_excluded` |
| 4 | inside the Russian allocation, no CDN exclusion | DIRECT | `allocation_direct` |
| 5 | unknown or uncovered destination | PROXY | `no_trusted_evidence` |
| 6 | required direct egress unavailable | DROP, no automatic switch | `direct_egress_unavailable` in the drop ledger |

Row 1 is evaluated before every input that could ask for DIRECT (`egressInput`),
so an operator rule — including an inventory override that names a private or
internal range — cannot promote such a destination. Rows 3 to 5 are the
classifier's answer, and row 5 is the fail-safe default: a destination nobody can
classify is proxied, never routed direct by omission.

Row 6 is realised where the availability is known rather than inside
`decideEgress`. A DIRECT dispatch that the direct-egress manager refuses is
recorded as a DROP with the producer's own token
(`forwarder.recordDirectRefusal`, `drop_refusal.go`) and is never re-decided as
PROXY: a direct path that cannot deliver must not be reported as a working proxy
path, which is what re-deciding the packet would do.

Two things are applied around the contract, not inside it:

- **An existing flow keeps its choice** (`handleStickyFlow`, `pumps.go`). A flow
  entry is created once per (session, route generation, 5-tuple) and is reused
  while it lives, so a later packet on the same tuple is dispatched on the choice
  the entry already holds — the entry keeps the reason it was created with, and no
  new destination decision is taken. Retiring the entry and re-admitting the tuple
  creates a new entry, so a reused tuple is a new incarnation by construction.
- **A protocol that cannot be NATed takes the proxy fallback** — anything that is
  not TCP or UDP, such as ICMP. That is a fact about the transport, not about the
  destination: it is applied after row 1 and before the decided route is acted on,
  and it records no destination reason because no destination decided it.

## 3. Activation

`vpn.ValidatePBRPrerequisites` (`internal/vpn/vpn_pbr.go`) refuses activation
unless all four of these hold:

| Prerequisite | Refusal |
| :--- | :--- |
| a valid, non-loopback, non-unspecified host WAN IPv4 address | `ErrPBRMissingHostWAN` |
| an attached WAN packet device | `ErrPBRMissingWANDevice` |
| a policy matcher (the operator's override rules are published into it) | `ErrPBRMissingPolicy` |
| an installed destination classifier | `ErrPBRMissingClassifier` |

**The rule count is not a prerequisite.** A record that overrides nothing is a
valid policy: with zero operator exceptions rows 3 to 5 still decide every
destination from the classifier, and the activation handshake
(`vpn.ensureInitialSnapshot`) publishes that empty snapshot rather than refusing
it. What must never activate is a data path with no classifier, because every
destination would then answer "uncovered", row 5 would take all traffic, nothing
could ever route DIRECT, and the panel would report a policy that does nothing.

A classifier that cannot be built refuses activation for the same reason:
`buildDestinationClassifier` returns nil when the committed inventory or the
embedded ASN table is unusable, and the refusal is reported through the policy
status instead of a panel that quietly never turns routing on. A refused update to
an already-live data path leaves the incumbent classifier and rules still
installed (`updateLivePolicyRouting`).

Disabling — an explicit disable, a refused activation, or a service start with
the record disabled — removes both the classifier and the direct-egress manager
(`ConfigurePBR`, `TeardownPBR`), so no stale classification survives into the next
activation.

## 4. The operator PROXY exception list

Stored in the policy settings record under `proxy_exceptions`, edited in the
policy section of the settings page (`web/templates/settings_policy.html`,
`web/static/js/policy_routing.js`) and saved through `PUT /api/vpn/policy`:

- one IPv4 prefix or address per line; blank lines and comments are ignored;
- at most `policy.MaxLocalExceptions` (4096) entries;
- a line that is not an IPv4 prefix is refused with
  `policy.ErrLocalRuleNotPrefix`, because a domain line would be stored and never
  matched against a packet — a control that looks configured and decides nothing;
- the list is deliberately **not** checked against the prohibited set. Row 1
  outranks it, so an entry naming a private range cannot route that range; the one
  authoritative prohibited set lives in the forwarder and is not restated in
  validation;
- an empty list is a valid configuration and the shortest deliberate edit. There
  is no rule-count floor and no shrink guard: the authority is the classifier, so
  removing the last entry is an edit, not evidence of a broken transfer.

The list is compiled into the published policy snapshot, and the packet path
matches it with `policySnapshot.MatchIPv4` (`routeClientPBR`). A live save
publishes the new snapshot into the existing matcher, so a rules change takes
effect without rebuilding the data path or interrupting live flows.

A save that omits `proxy_exceptions` keeps the stored list; an explicit empty
array clears it. The merge runs inside the serialized settings mutation and
validates the result before anything is written (`mergeStoredProxyExceptions`).

`sync_interval_seconds` bounds how often that cycle re-compiles and republishes
the record (`policy.MinSyncInterval` 30 minutes, `policy.MaxSyncInterval` 24
hours, default 6 hours). The cycle fetches nothing — a compiled snapshot holds the
operator's prefixes and no remote list — so the interval is a schedule, not a
download cadence, and a save publishes immediately rather than waiting for it.

## 5. The operator inventory override

The committed allocation set is the baseline; `inventory_override` lets a
deployment correct or extend it without waiting for a release.

- one IPv4 prefix per line, at most `policy.MaxInventoryOverrideEntries` (4096);
- a body with no prefix, a mistyped address such as `203.0.113.999`, or an
  IPv6-only body is refused with `400` and the stored record is left exactly as it
  was, so a typo cannot persist as an override that applies nothing. A body that
  also carries a domain rule is refused as a whole
  (`policy.ErrInventoryOverrideNotPrefixOnly`) rather than stored as an override
  that would apply only part of what was submitted;
- it takes precedence over the shipped set for every address it contains; an
  address it does not name keeps the committed answer
  (`policy.Inventory.WithOverride`, `Inventory.Match` reports which set answered);
- it answers set membership only. Row 1 (prohibited/internal) and row 2 (explicit
  PROXY) still outrank it;
- it is applied on activation and on an accepted save while routing is live; the
  classifier is replaced rather than the data path rebuilt;
- the policy status reports it beside the shipped set — the shipped prefix count,
  source, retrieval date and digest stay the shipped set's own facts, and the
  override's count and digest are reported as the override
  (`policy.InventoryStatus`). An override is never presented as part of the
  committed artifact.

## 6. Prohibited and internal destinations

The address-side guard is `forwarder.IsProhibitedIPv4Destination`
(`direct_egress_validation.go`), applied as `ValidateDirectDestination`:

- invalid, unspecified, loopback, link-local, multicast and non-IPv4 destinations;
- RFC1918, CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), TEST-NET
  blocks, IETF protocol assignments, reserved space and broadcast;
- anything in the first octet's zero block.

The panel serves no DNS of its own, so the gateway address issued client profiles
formerly named as their resolver is an ordinary private destination here: a packet
to it is refused like any other internal destination, on every port, under the
policy path.

## 7. What classification does not mean

- **Allocation is not hosting location.** Membership is an approximation from RIR
  delegation, not from BGP origin: Yandex prefixes are originated by a
  Serbian-registered network, so an ASN-country lookup reports `RS` for Russian
  space. The reason token says `allocation_direct`, never "hosted in Russia".
- **Reachability is a separate question.** A direct flow still egresses through
  this host's own WAN address, so a service that refuses foreign source addresses
  still fails. The per-flow record keeps *routed direct and written to WAN*
  distinct from *routed direct and failed* (`FlowForwardWritten`,
  `FlowForwardFailed`): the second is the signal that the egress location, not the
  classifier, is the problem.
- **A successful WAN write is not proof the application worked.** It records that
  the packet left through this host's WAN interface and nothing about the reply.
  The return direction is a separate observation, reported as `not_observed` when
  no reply was seen.
- **The CDN exclusion list is conservative.** `geodb.KnownCDNASNs` holds ten ASNs
  — Cloudflare (AS13335, AS209242), Fastly (AS54113), Akamai (AS20940, AS16625,
  AS35994), Amazon (AS16509, AS14618), Google (AS15169) and Microsoft (AS8075).
  It is an exclusion list, not complete CDN detection: a Russian service behind an
  unlisted CDN routes direct, and a listed range inside the allocation stays
  proxied. The set the classifier consults is published to the operator
  (`geodb.CDNExclusions`, `PolicyStatus.CDN`), read from the same table
  `IsMultiRegionCDNASN` matches against, so the reported list cannot drift from
  the deciding one.
- **No destination evidence is consulted.** The destination address is the only
  routing input; the per-flow record documents a decision, it does not make one.

## 8. Reported state

Reading a decision is part of the contract, because "why was this proxied" is the
question an operator actually asks.

`vpn.PolicyStatus` (`PolicyStatusSnapshot`) reports the live picture on the
existing policy endpoints (`GET /api/vpn/policy`, `GET /api/vpn/policy/stats` —
admin-only, `internal/router/router.go`):

| Field | Meaning |
| :--- | :--- |
| `enabled`, `ready`, `sync_state` | whether the data path is on, whether a snapshot is published, and the last outcome |
| `generation_id`, `version`, `cidr_count` | identity of the published snapshot and how many override rules it holds |
| `last_sync_time`, `last_success`, `last_error` | when the compile cycle last ran, succeeded or failed |
| `inventory` | the committed artifact's source, retrieval date, digest, prefix count, age against the staleness threshold, and the override's own count and digest |
| `cdn` | the exclusion set in force, with `error` set when it cannot be described |

Per-flow evidence — decision time, policy generation, reason token, backend
tunnel, forward/return counters and dispatch outcome — is held by the forwarder
and rendered by the client diagnosis (`decision_reason`). A refusal before any
flow exists is recorded in the drop ledger instead, with the producer's token.

## 9. Limitations

- **IPv4 only.** The policy path parses an IPv4 client packet
  (`ParseAndValidateClientIPv4`); anything else — an IPv6 packet included — is
  refused before any decision is taken and recorded under `invalid_client_packet`,
  so it is not forwarded while policy routing is active. With policy routing
  disabled the legacy path tunnels the same packet unchanged. The classifier
  reports a non-IPv4 destination as unclassified, and an override body is
  validated as an IPv4 prefix list, so an IPv6-only body is refused rather than
  stored as an override that would apply nothing.
- **No domain input at any layer.** A record's domain rules belong to an earlier
  build; see §10.
- **The classifier proves allocation, not geography.** A destination outside the
  allocation is proxied even when the service is Russian, and one inside it routes
  direct when no CDN exclusion applies, even when the service is not Russian.
- **A stale inventory is not silently authoritative.** The artifact's age is
  reported against `policy.DefaultInventoryMaxAge` (180 days) and `stale` is set
  when it is exceeded; an unusable artifact is reported as an error rather than as
  an empty set, because "every address is Russian" and "every address is proxied"
  must never look the same.

## 10. Upgrading a record written by an earlier build

The exception list was renamed from `local_entries` to `proxy_exceptions` when
domain rules were retired, and earlier builds also stored a source selection, a
custom list URL set and an excluded-domain list. Reading those bytes is a
transition with two readers (`internal/policy/settings_legacy.go`):

- **Stored bytes** go through `policy.DecodeStoredRecord`, which keeps the entries
  this build can apply and reports the rest. A stored row is allowed to hold
  content this build has no rule for; failing the whole record would take a
  working IPv4 policy down with an inert entry.
- **A request body** goes through `Settings.UnmarshalJSON`, which filters nothing:
  an unusable entry has to reach `Validate` so the request is refused whole. A
  lenient wire decoder would answer `200` for a save that silently dropped the
  operator's PROXY override.
- The two readers share one field-decode step, so they differ in exactly one
  decision: what to do with a predecessor list.
- `GET /api/vpn/policy` reports what could not be carried as `retired`
  (`policy.ReviewStoredRecord`: source selection, custom URL count, excluded
  domain count and the non-IPv4 entries verbatim), so a shorter list is an
  explained downgrade rather than an apparent loss.
- Presence is not length: an explicitly empty list stays empty. Treating it as "no
  key here" would merge the stored entries back and answer `200` while the old
  list stayed installed.
