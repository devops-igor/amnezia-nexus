package vpn

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// This file is test-only observation support for the payload leg of the
// differential matrix. That leg asserts a UDP echo and only then tears the
// client and the subject down, so a failing exchange used to be reported after
// the fixture had destroyed the state that explains it: the client device was
// closed, the subject engine was stopped and the backend pumps were joined.
//
// The snapshot below is read through existing accessors BEFORE that teardown:
// the client device's UAPI byte counters and handshake time, the subject
// portal's per-peer counters and ingress.Router.StatsSnapshot.
//
// The report is an allowlist, not a filter. Every field is an unsigned integer
// or one of the existing handshake enums, so keys, packet bytes, endpoints,
// addresses, session/peer identity and arbitrary error text cannot be
// represented in a snapshot at all. A failed or unreadable read is emitted as
// "unknown", never as zero, so an unavailable observation can never be
// mistaken for a measured one.

// counterReading distinguishes "measured as N" from "could not be read".
// A genuine zero therefore stays distinguishable from an unavailable value.
type counterReading struct {
	known bool
	value uint64
}

// udpExchangeSnapshot is the complete pre-teardown record for one UDP exchange.
// It deliberately has no string or byte field, which is what makes the report
// structurally incapable of carrying secret or identity material.
type udpExchangeSnapshot struct {
	Phase           handshakePhase
	ClientHandshake handshakeOutcome
	ClientTx        counterReading
	ClientRx        counterReading
	PortalHandshake handshakeOutcome
	PortalPeers     counterReading
	PortalRx        counterReading
	PortalTx        counterReading
	Router          ingress.Stats
	RouterKnown     bool
}

// parseClientByteCounters reads ONLY the two upstream byte counters from a
// client UAPI dump. Every other line -- private and public keys, endpoints,
// allowed IPs and packet payloads -- is skipped rather than parsed, so the
// surrounding text can never reach the report. A missing or malformed counter
// stays unknown instead of defaulting to zero.
func parseClientByteCounters(uapi string) (tx, rx counterReading) {
	for _, line := range strings.Split(uapi, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "tx_bytes":
			tx = readUAPICounter(value)
		case "rx_bytes":
			rx = readUAPICounter(value)
		}
	}
	return tx, rx
}

// readUAPICounter converts one decimal counter value, reporting malformed input
// as unknown.
func readUAPICounter(value string) counterReading {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return counterReading{}
	}
	return counterReading{known: true, value: n}
}

// handshakePresence maps a parsed-and-possibly-unavailable handshake time onto
// the tri-state outcome. A read or parse failure means unknown, not "did not
// happen": the two are different observations and the failure output must not
// confuse them.
func handshakePresence(at time.Time, err error) handshakeOutcome {
	switch {
	case err != nil:
		return handshakeOutcomeUnknown
	case at.IsZero():
		return handshakeOutcomeNotCompleted
	default:
		return handshakeOutcomeCompleted
	}
}

// captureUDPExchangeSnapshot reads the failure-relevant state through existing
// accessors. It must run BEFORE the fixture closes the client, stops the
// subject engine or joins its backend pumps: afterwards every read reports
// unknown, which is exactly the loss this snapshot exists to prevent.
//
// The three reads are separable observations owned by three different
// components, so each is captured by its own helper below and a failure in one
// cannot suppress the others.
func captureUDPExchangeSnapshot(client *HarnessClient, sub *SubjectServer) udpExchangeSnapshot {
	snap := udpExchangeSnapshot{
		Phase:           phaseSubject,
		ClientHandshake: handshakeOutcomeUnknown,
		PortalHandshake: handshakeOutcomeUnknown,
	}
	captureClientState(&snap, client)
	if sub == nil || sub.engine == nil {
		return snap
	}
	capturePortalState(&snap, sub.engine.Portal())
	captureRouterState(&snap, sub.engine.Router())
	return snap
}

// captureClientState records the client device's byte counters and handshake
// presence. The UAPI text is consumed by the two allowlisted parsers and is
// never returned, stored or logged; an unreadable device leaves both fields
// unknown.
func captureClientState(snap *udpExchangeSnapshot, client *HarnessClient) {
	if client == nil {
		return
	}
	raw, err := client.IpcGet()
	if err != nil {
		return
	}
	snap.ClientTx, snap.ClientRx = parseClientByteCounters(raw)
	snap.ClientHandshake = handshakePresence(parseHandshakeCompletion(raw))
}

// capturePortalState records the portal's peer count, aggregate byte counters
// and handshake presence. Counters are aggregated across the peer list rather
// than selected by identity, so no peer key, endpoint or address is read out of
// the status projection.
func capturePortalState(snap *udpExchangeSnapshot, portal *clientawg.ClientAWGDevice) {
	if portal == nil {
		return
	}
	st, err := portal.Status()
	if err != nil {
		return
	}
	var rx, tx uint64
	presence := handshakeOutcomeNotCompleted
	for _, peer := range st.Peers {
		rx += peer.ReceiveBytes
		tx += peer.TransmitBytes
		if !peer.LastHandshake.IsZero() {
			presence = handshakeOutcomeCompleted
		}
	}
	snap.PortalPeers = counterReading{known: true, value: uint64(len(st.Peers))}
	snap.PortalRx = counterReading{known: true, value: rx}
	snap.PortalTx = counterReading{known: true, value: tx}
	snap.PortalHandshake = presence
}

// captureRouterState records the ingress router's admission and drop counters,
// which is the fact that was missing entirely from the CI failure.
func captureRouterState(snap *udpExchangeSnapshot, router *ingress.Router) {
	if router == nil {
		return
	}
	snap.Router = router.StatsSnapshot()
	snap.RouterKnown = true
}

// udpSnapshotRouterKeys names the router counters in emission order. The order
// is fixed here so the validated role of each value cannot drift.
var udpSnapshotRouterKeys = [...]string{
	"router_admitted_sessions",
	"router_malformed_packet_drops",
	"router_unmapped_source_ip_drops",
	"router_ownership_mismatch_drops",
	"router_no_active_backend_drops",
	"router_admission_rejected_drops",
	"router_route_registration_errors",
}

// udpSnapshotRouterValues returns the router counters in udpSnapshotRouterKeys
// order.
func udpSnapshotRouterValues(st ingress.Stats) []uint64 {
	return []uint64{
		st.AdmittedSessions,
		st.MalformedPacketDrops,
		st.UnmappedSourceIPDrops,
		st.OwnershipMismatchDrops,
		st.NoActiveBackendDrops,
		st.AdmissionRejectedDrops,
		st.RouteRegistrationErrors,
	}
}

// writeCounter emits one counter as key=value, or key=unknown when the read did
// not produce a measurement.
func writeCounter(b *strings.Builder, key string, c counterReading) {
	if !c.known {
		fmt.Fprintf(b, " %s=unknown", key)
		return
	}
	fmt.Fprintf(b, " %s=%d", key, c.value)
}

// String renders the snapshot as a single line of space-separated key=value
// tokens. Values are the existing handshake enum, an unsigned counter or
// "unknown"; there is no free-text field to render.
func (s udpExchangeSnapshot) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "udp_exchange_snapshot: phase=%s client_handshake=%s", s.Phase, s.ClientHandshake)
	writeCounter(&b, "client_tx_bytes", s.ClientTx)
	writeCounter(&b, "client_rx_bytes", s.ClientRx)
	fmt.Fprintf(&b, " portal_handshake=%s", s.PortalHandshake)
	writeCounter(&b, "portal_peers", s.PortalPeers)
	writeCounter(&b, "portal_rx_bytes", s.PortalRx)
	writeCounter(&b, "portal_tx_bytes", s.PortalTx)

	values := udpSnapshotRouterValues(s.Router)
	for i, key := range udpSnapshotRouterKeys {
		if !s.RouterKnown {
			fmt.Fprintf(&b, " %s=unknown", key)
			continue
		}
		fmt.Fprintf(&b, " %s=%d", key, values[i])
	}
	return b.String()
}

// udpSnapshotKeys is the closed set of keys the report may emit. A key that is
// not listed here cannot be added to the CI output by accident.
var udpSnapshotKeys = map[string]struct{}{
	"phase":                            {},
	"client_handshake":                 {},
	"client_tx_bytes":                  {},
	"client_rx_bytes":                  {},
	"portal_handshake":                 {},
	"portal_peers":                     {},
	"portal_rx_bytes":                  {},
	"portal_tx_bytes":                  {},
	"router_admitted_sessions":         {},
	"router_malformed_packet_drops":    {},
	"router_unmapped_source_ip_drops":  {},
	"router_ownership_mismatch_drops":  {},
	"router_no_active_backend_drops":   {},
	"router_admission_rejected_drops":  {},
	"router_route_registration_errors": {},
}

// Value grammar: a lowercase enum token of at most 16 characters (which covers
// "completed", "not_completed", "unknown" and the phase names) or a decimal
// counter of at most 12 digits. Uppercase, base64/hex payloads, dotted or
// colon-separated addresses and absolute epoch seconds nanoseconds cannot match.
var udpSnapshotValuePattern = regexp.MustCompile(`^(?:[a-z][a-z0-9_]{0,15}|[0-9]{1,12})$`)

// udpSnapshotPrefix is the fixed leading token of an emitted snapshot line.
const udpSnapshotPrefix = "udp_exchange_snapshot:"

// validateUDPExchangeSnapshot enforces the emitted schema, so a future edit that
// tried to pass bytes, a key, an address or an absolute timestamp cannot reach
// the failure output unnoticed. Every token must be exactly one key=value with
// an allowlisted key, and every allowlisted key must appear exactly once.
func validateUDPExchangeSnapshot(line string) error {
	tokens := strings.Fields(strings.TrimPrefix(line, udpSnapshotPrefix))
	if len(tokens) != len(udpSnapshotKeys) {
		return fmt.Errorf("schema: got %d tokens, want %d", len(tokens), len(udpSnapshotKeys))
	}
	seen := make(map[string]struct{}, len(tokens))
	for i, token := range tokens {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			return fmt.Errorf("schema: token %d is not key=value", i)
		}
		if _, allowed := udpSnapshotKeys[key]; !allowed {
			return fmt.Errorf("schema: token %d key %q is not allowlisted", i, key)
		}
		if !udpSnapshotValuePattern.MatchString(value) {
			return fmt.Errorf("schema: token %d value for key %q is not an enum token or bounded count", i, key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("schema: token %d repeats key %q", i, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// udpExchangeSnapshotSuffix renders and schema-validates a snapshot for
// appending to a failure message. A schema violation is suppressed rather than
// printed: a formatter regression must never become leak-shaped CI output. The
// returned text starts on the line after the failure message.
func udpExchangeSnapshotSuffix(snap udpExchangeSnapshot) string {
	line := snap.String()
	if err := validateUDPExchangeSnapshot(line); err != nil {
		return " " + udpSnapshotPrefix + " suppressed"
	}
	return "\n    " + line
}

// udpExchangeFailed reports whether the exchange should be treated as a
// failure. It is the same predicate the call site asserts with, kept in one
// place so the report and the assertion cannot disagree.
func udpExchangeFailed(err error, echo, payload []byte) bool {
	return err != nil || !bytes.Equal(echo, payload)
}

// udpExchangeFailureReport captures the pre-teardown state and renders it for
// the failure message. It is called before the fixture closes the connection,
// the client and the subject, because those calls destroy exactly the device and
// admission state that explains a lost exchange.
//
// A passing exchange returns "" without reading anything: the snapshot costs
// nothing on the success path and adds no permanent telemetry. Only a failure
// pays for the reads, and the ordinary go test failure output is the collector
// that survives job teardown.
func udpExchangeFailureReport(client *HarnessClient, sub *SubjectServer, err error, echo, payload []byte) string {
	if !udpExchangeFailed(err, echo, payload) {
		return ""
	}
	return udpExchangeSnapshotSuffix(captureUDPExchangeSnapshot(client, sub))
}

// TestUDPExchangeSnapshotFormatter covers the positive formatting contract:
// every allowlisted key is emitted once, a known counter renders its value, and
// an unavailable read or router renders unknown instead of a fabricated zero.
func TestUDPExchangeSnapshotFormatter(t *testing.T) {
	t.Run("measured state validates and reports values", func(t *testing.T) {
		snap := udpExchangeSnapshot{
			Phase:           phaseSubject,
			ClientHandshake: handshakeOutcomeCompleted,
			ClientTx:        counterReading{known: true, value: 1263},
			ClientRx:        counterReading{known: true, value: 92},
			PortalHandshake: handshakeOutcomeCompleted,
			PortalPeers:     counterReading{known: true, value: 1},
			PortalRx:        counterReading{known: true, value: 180},
			PortalTx:        counterReading{known: true, value: 192},
			Router:          ingress.Stats{AdmittedSessions: 1, AdmissionRejectedDrops: 2},
			RouterKnown:     true,
		}
		line := snap.String()
		if err := validateUDPExchangeSnapshot(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		for _, want := range []string{
			"phase=sub",
			"client_handshake=completed",
			"client_tx_bytes=1263",
			"client_rx_bytes=92",
			"portal_handshake=completed",
			"portal_peers=1",
			"portal_rx_bytes=180",
			"router_admitted_sessions=1",
			"router_admission_rejected_drops=2",
		} {
			if !strings.Contains(line, want) {
				t.Errorf("output %q missing %q", line, want)
			}
		}
		if strings.Count(line, "\n") != 0 {
			t.Errorf("report must be one line in the failure console, got %q", line)
		}
	})

	t.Run("unavailable reads report unknown not zero", func(t *testing.T) {
		snap := udpExchangeSnapshot{Phase: phaseSubject}
		line := snap.String()
		if err := validateUDPExchangeSnapshot(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		for _, want := range []string{
			"client_handshake=unknown",
			"client_tx_bytes=unknown",
			"client_rx_bytes=unknown",
			"portal_handshake=unknown",
			"portal_peers=unknown",
			"portal_rx_bytes=unknown",
			"portal_tx_bytes=unknown",
			"router_admitted_sessions=unknown",
			"router_route_registration_errors=unknown",
		} {
			if !strings.Contains(line, want) {
				t.Errorf("output %q missing %q", line, want)
			}
		}
		for _, forbidden := range []string{"client_tx_bytes=0", "router_admitted_sessions=0", "portal_handshake=not_completed"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("output %q fabricated %q", line, forbidden)
			}
		}
	})

	t.Run("negative counter values are not rendered as numbers", func(t *testing.T) {
		// The upstream UAPI is text; a negative or malformed value must not
		// become a measured reading.
		tx, rx := parseClientByteCounters("tx_bytes=-5\nrx_bytes=abc\n")
		if tx.known || rx.known {
			t.Fatalf("malformed counters reported as known: %+v %+v", tx, rx)
		}
		line := udpExchangeSnapshot{Phase: phaseSubject, ClientTx: tx, ClientRx: rx}.String()
		if strings.Contains(line, "client_tx_bytes=-") || strings.Contains(line, "client_rx_bytes=-") {
			t.Fatalf("negative counter reached the report: %q", line)
		}
	})
}

// assertNoWallClockFields fails if t or any reachable field is a wall-clock type.
// The snapshot reports handshake PRESENCE, never a handshake TIME, so absolute
// epoch state has no representation to leak.
func assertNoWallClockFields(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Struct:
		if typ == reflect.TypeOf(time.Time{}) {
			t.Fatalf("%s is a wall-clock time: absolute epoch state could reach the report", path)
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			assertNoWallClockFields(t, f.Type, path+"."+f.Name)
		}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		assertNoWallClockFields(t, typ.Elem(), path+"[]")
	}
}

// TestParseClientByteCounters pins the allowlist behaviour of the client-side
// parser: only the two byte counters are read, and the rest of the UAPI dump --
// key material, endpoints, addresses, payload-shaped values -- is skipped.
func TestParseClientByteCounters(t *testing.T) {
	uapi := strings.Join([]string{
		"private_key=00000000000000000000000000000000000000000000000000000000000000ff",
		"public_key=1111111111111111111111111111111111111111111111111111111111111111",
		"endpoint=192.0.2.55:51820",
		"allowed_ip=10.100.0.2/32",
		"last_handshake_time_sec=1794000000",
		"tx_bytes=1263",
		"rx_bytes=92",
		"payload=diff-matrix-Standard_Profile-payload",
		"tx_bytes_extra=HOSTILE_COUNTER_9f2e",
	}, "\n")

	tx, rx := parseClientByteCounters(uapi)
	if !tx.known || tx.value != 1263 {
		t.Fatalf("tx = %+v, want known 1263", tx)
	}
	if !rx.known || rx.value != 92 {
		t.Fatalf("rx = %+v, want known 92", rx)
	}

	for name, empty := range map[string]string{
		"empty":     "",
		"unrelated": "private_key=ff\nlisten_port=51820\n",
	} {
		if tx, rx := parseClientByteCounters(empty); tx.known || rx.known {
			t.Errorf("%s: counters reported as known: %+v %+v", name, tx, rx)
		}
	}
}

// TestUDPExchangeSnapshotPrivacyControls is the negative half: the snapshot type
// must be structurally incapable of carrying free text, and a hostile client
// state must not add anything to the report beyond the allowlisted facts.
func TestUDPExchangeSnapshotPrivacyControls(t *testing.T) {
	t.Run("snapshot type carries no string or byte field", func(t *testing.T) {
		assertNoStringLikeFields(t, reflect.TypeOf(udpExchangeSnapshot{}), "udpExchangeSnapshot")
	})

	// Counter values are decimal, so a digit-count rule cannot tell an absolute
	// epoch-seconds reading from a byte count. The guarantee has to be
	// structural instead: the snapshot carries no time value at all, only
	// presence enums, so wall-clock state cannot be represented in the first
	// place.
	t.Run("snapshot type carries no wall-clock field", func(t *testing.T) {
		assertNoWallClockFields(t, reflect.TypeOf(udpExchangeSnapshot{}), "udpExchangeSnapshot")
	})

	t.Run("schema rejects leak-shaped values", func(t *testing.T) {
		base := udpExchangeSnapshot{Phase: phaseSubject}.String()
		cases := map[string]string{
			"uppercase base64 key":   strings.Replace(base, "client_handshake=unknown", "client_handshake=QWxhZGRpbjpvcGVuIHNlc2FtZQ==", 1),
			"long lowercase hex key": strings.Replace(base, "client_handshake=unknown", "client_handshake="+strings.Repeat("ab", 32), 1),
			"ipv4 endpoint":          strings.Replace(base, "client_handshake=unknown", "client_handshake=192.0.2.55:51820", 1),
			"test payload":           strings.Replace(base, "client_handshake=unknown", "client_handshake=diff-matrix-payload", 1),
			"session identity":       strings.Replace(base, "client_handshake=unknown", "client_handshake=9a3d2464-ac80-41b2-85ca-3af70efccc09", 1),
			"bare token":             base + " deadbeef",
			"non allowlisted key":    strings.Replace(base, "client_handshake=unknown", "private_key=abc", 1),
			"duplicated key":         strings.Replace(base, "client_tx_bytes=unknown", "client_rx_bytes=unknown", 1),
		}
		for name, line := range cases {
			if err := validateUDPExchangeSnapshot(line); err == nil {
				t.Errorf("%s: validator accepted leak-shaped output %q", name, line)
			}
		}
	})

	t.Run("hostile client state adds no free text", func(t *testing.T) {
		hostile := strings.Join([]string{
			"private_key=00000000000000000000000000000000000000000000000000000000000000ff",
			"endpoint=198.51.100.7:51820",
			"allowed_ip=10.100.0.2/32",
			"payload=HOSTILE_PAYLOAD_c4a1",
			"tx_bytes=7",
			"rx_bytes=9",
		}, "\n")
		tx, rx := parseClientByteCounters(hostile)
		at, err := parseHandshakeCompletion(hostile)
		snap := udpExchangeSnapshot{
			Phase:           phaseSubject,
			ClientHandshake: handshakePresence(at, err),
			ClientTx:        tx,
			ClientRx:        rx,
		}
		suffix := udpExchangeSnapshotSuffix(snap)
		for _, marker := range hostileUDPMarkers {
			if strings.Contains(suffix, marker) {
				t.Errorf("report leaked %q: %q", marker, suffix)
			}
		}
		if !strings.Contains(suffix, "client_tx_bytes=7") || !strings.Contains(suffix, "client_rx_bytes=9") {
			t.Errorf("report dropped the measured counters: %q", suffix)
		}
		if !strings.Contains(suffix, "client_handshake=not_completed") {
			t.Errorf("report lost the handshake presence fact: %q", suffix)
		}
	})
}

// hostileUDPMarkers are the substrings the report must never reproduce. All of
// them appear in the hostile client state used above, so the leak assertions
// cannot pass vacuously. The absolute handshake epoch is included because a
// relative-presence report must never expose wall-clock state.
var hostileUDPMarkers = []string{
	"00000000000000000000000000000000000000000000000000000000000000ff",
	"198.51.100.7",
	"10.100.0.2",
	"HOSTILE_PAYLOAD_c4a1",
	"1794000000",
	"private_key",
}

// TestUDPExchangeSnapshotPositiveControl is the decisive positive control: on a
// successful exchange the snapshot must show a completed handshake on both ends,
// non-zero portal traffic and an admission, all read from the live fixture.
// A snapshot that reported zeros regardless of state would be worthless.
func TestUDPExchangeSnapshotPositiveControl(t *testing.T) {
	harness := NewDifferentialHarness(t)
	payload := []byte("udp-snapshot-positive-control")

	sub, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}
	defer func() { _ = harness.StopSubjectServer(sub) }()

	client, err := harness.NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	udpConn, err := client.DialUDP()
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}

	echo, exchangeErr := client.ExchangeUDP(udpConn, payload)
	// Capture before closing the connection, the client and the subject: that
	// ordering is the whole point of this fixture.
	snap := captureUDPExchangeSnapshot(client, sub)
	_ = udpConn.Close()

	if exchangeErr != nil || !bytes.Equal(echo, payload) {
		t.Fatalf("positive control exchange failed: got %q, err %v%s", echo, exchangeErr, udpExchangeSnapshotSuffix(snap))
	}

	if err := validateUDPExchangeSnapshot(snap.String()); err != nil {
		t.Fatalf("positive control report violates its schema: %v", err)
	}
	if snap.ClientHandshake != handshakeOutcomeCompleted {
		t.Errorf("client handshake = %s, want completed", snap.ClientHandshake)
	}
	if snap.PortalHandshake != handshakeOutcomeCompleted {
		t.Errorf("portal handshake = %s, want completed", snap.PortalHandshake)
	}
	if !snap.PortalPeers.known || snap.PortalPeers.value != 1 {
		t.Errorf("portal peers = %+v, want exactly one observed peer", snap.PortalPeers)
	}
	if !snap.PortalRx.known || snap.PortalRx.value == 0 {
		t.Errorf("portal rx = %+v, want a non-zero measured count", snap.PortalRx)
	}
	if !snap.PortalTx.known || snap.PortalTx.value == 0 {
		t.Errorf("portal tx = %+v, want a non-zero measured count", snap.PortalTx)
	}
	if !snap.RouterKnown || snap.Router.AdmittedSessions == 0 {
		t.Errorf("router admission = %+v known=%t, want at least one admitted session", snap.Router, snap.RouterKnown)
	}
	// The positive control must be clearly distinguishable from a failure.
	if strings.Contains(snap.String(), "=unknown") {
		t.Errorf("measured positive control still reports unknown: %q", snap.String())
	}
}

// TestUDPExchangeSnapshotHelperProcess is not a real test: it is the controlled
// failing fixture that TestUDPExchangeSnapshotControlledFailureOutput runs in a
// child process, so the real failure-report path is exercised for real.
func TestUDPExchangeSnapshotHelperProcess(t *testing.T) {
	if os.Getenv("UDP_SNAPSHOT_HELPER") != "1" {
		t.Skip("helper process only")
	}
	t.Fatalf("sub ExchangeUDP failed for %s: got %q, err udp exchange timed out after 5 attempts%s",
		"Controlled_Fixture", "", udpExchangeSnapshotSuffix(hostileUDPExchangeSnapshot()))
}

// hostileUDPExchangeSnapshot builds a snapshot from parse-hostile client state
// plus synthetic counters, so the child process emits a report shaped exactly
// like a real failure while carrying material that must not survive.
func hostileUDPExchangeSnapshot() udpExchangeSnapshot {
	hostile := strings.Join([]string{
		"private_key=00000000000000000000000000000000000000000000000000000000000000ff",
		"endpoint=198.51.100.7:51820",
		"allowed_ip=10.100.0.2/32",
		"last_handshake_time_sec=1794000000",
		"last_handshake_time_nsec=250000000",
		"tx_bytes=1263",
		"rx_bytes=92",
		"payload=HOSTILE_PAYLOAD_c4a1",
	}, "\n")

	tx, rx := parseClientByteCounters(hostile)
	at, err := parseHandshakeCompletion(hostile)
	if err != nil {
		return udpExchangeSnapshot{Phase: phaseSubject}
	}
	return udpExchangeSnapshot{
		Phase:           phaseSubject,
		ClientHandshake: handshakePresence(at, err),
		ClientTx:        tx,
		ClientRx:        rx,
		PortalHandshake: handshakeOutcomeCompleted,
		PortalPeers:     counterReading{known: true, value: 1},
		PortalRx:        counterReading{known: true, value: 180},
		PortalTx:        counterReading{known: true, value: 192},
		Router:          ingress.Stats{AdmissionRejectedDrops: 5},
		RouterKnown:     true,
	}
}

// TestUDPExchangeSnapshotControlledFailureOutput runs the controlled failing
// fixture in a real child process and checks the two properties that matter: the
// original failure exit is retained, and the failure output carries the bounded
// facts with none of the hostile material.
func TestUDPExchangeSnapshotControlledFailureOutput(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestUDPExchangeSnapshotHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "UDP_SNAPSHOT_HELPER=1")

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("controlled failing fixture exited zero; a failed exchange must stay a failing test")
	}

	text := string(out)
	if !strings.Contains(text, udpSnapshotPrefix) {
		t.Fatalf("failing output is missing the pre-teardown snapshot:\n%s", text)
	}
	for _, want := range []string{
		"client_handshake=completed",
		"client_tx_bytes=1263",
		"client_rx_bytes=92",
		"portal_handshake=completed",
		"portal_rx_bytes=180",
		"portal_tx_bytes=192",
		"router_admission_rejected_drops=5",
		"router_admitted_sessions=0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("failing output is missing %q:\n%s", want, text)
		}
	}
	for _, marker := range hostileUDPMarkers {
		if strings.Contains(text, marker) {
			t.Errorf("failing output leaked %q:\n%s", marker, text)
		}
	}
}
