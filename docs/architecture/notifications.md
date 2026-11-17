# Notification engine and Gotify delivery

Owning package: `internal/notifications`. Persistence: `internal/database`
(`notification_events`, `notification_deliveries`,
`notification_producer_state`). Admin API: `internal/handlers/notifications.go`.

## Invariants

- External delivery is **off by default**. Disabled mode records events in local
  history and performs no outbound request.
- The portal owns event identity, incident identity, policy, history and retry.
  Gotify is a transport, not a second monitor.
- Events are durable facts; deliveries are independent retry state. A restart
  resumes unfinished attempts and cannot replay a purchase, setup, VPN change or
  any other producer operation.
- A producer transition and its event commit in **one transaction**. The
  producer-state row carries a generation, and the event key is derived from that
  generation, so an event-insert failure rolls the state back and the next poll
  retries exactly once instead of silently losing the alert.
- `EventKey` is producer-owned idempotency. A repeated key records one event and
  one delivery. `IncidentID` groups related transitions; recoveries reuse it.
- A delivered status means the Gotify endpoint accepted the HTTP request. It is
  not proof of mobile receipt and exactly-once delivery is not promised.
- An unknown or stale observation never becomes a confirmed outage or recovery.
  Observation state is persisted so a restart does not invent a transition.
- A newly created order or setup job may be announced even if its first observed
  state is already terminal; historical rows present at panel start are baselined
  instead of replaying old incidents.
- The application token is encrypted at rest and masked on every API read. It is
  sent only as the `X-Gotify-Key` header, never in the URL or an event payload.
- Destinations require HTTPS except a loopback test receiver. Redirects are
  refused, dial-time DNS is re-checked, and request timeouts are bounded.

## Producers

| Phase | Producer | Source |
| --- | --- | --- |
| 1 | Admin test event | explicit `POST /api/notifications/test` |
| 2 | `Observer` | existing reachability cache and persisted backend tunnel rows |
| 3 | `Observer` + order response boundary | Gigahost order ledger, provider acceptance response and setup intent states |
| 4 | `UpdateObserver` | `internal/service/upstream` release comparison |
| 5 | `FailoverProducer` | authoritative failover results from `internal/vpn` |

Phase 4 currently consumes the background monitoring inventory (AmneziaWG Go,
AmneziaWG Tools, pinned Docker base image). Per-server Xray/Naive/Caddy installed
versions remain owned by the on-demand server engine status path until a
background inventory exists; the notifier does not invent one.

Phase 5 automatic standby replacement events depend on #704, which is not
implemented. The producer wires the existing failover result and leaves
replacement outcomes to that subsystem when it lands.

## Dispatcher

One supervised worker polls due deliveries and sends with bounded backoff.
Transient outcomes retry; permanent 4xx outcomes fail; a missing response is
recorded as uncertain. Queue capacity is bounded and a saturated queue records a
truthful `dropped` outcome instead of blocking the producer.
