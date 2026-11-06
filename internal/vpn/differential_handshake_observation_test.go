package vpn

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This file is test-only observation support for the cold duplicate-initiation
// scenario. It records RELATIVE milestones and existing atomic shim counters on
// the failure path so that a dial timeout can be attributed to a latency envelope
// or to a handshake that never completed. It deliberately carries no free-text
// field: every emitted value is an enum token, a relative millisecond count or a
// counter, so packet bytes, keys, endpoints and absolute timestamps cannot be
// represented, let alone printed.

// handshakePhase names the differential phase whose dial is being observed.
type handshakePhase int

const (
	phaseReference handshakePhase = iota
	phaseSubject
)

func (p handshakePhase) String() string {
	switch p {
	case phaseReference:
		return "ref"
	case phaseSubject:
		return "sub"
	default:
		return "unknown"
	}
}

// handshakeOutcome reports whether the observed client completed a handshake.
// The zero value is deliberately "unknown": an unreadable or never-attempted
// observation must not masquerade as either completed or not completed.
type handshakeOutcome int

const (
	handshakeOutcomeUnknown handshakeOutcome = iota
	handshakeOutcomeCompleted
	handshakeOutcomeNotCompleted
)

func (o handshakeOutcome) String() string {
	switch o {
	case handshakeOutcomeCompleted:
		return "completed"
	case handshakeOutcomeNotCompleted:
		return "not_completed"
	default:
		return "unknown"
	}
}

// milestoneDelta is one shim-side milestone measured relative to dial start.
// observed distinguishes "not seen" from a genuine zero or negative delta.
type milestoneDelta struct {
	observed bool
	delta    time.Duration
}

// shimCounters is a point-in-time read of the existing UDPFaultShim atomics.
// It is not a single atomic transaction; each field is individually race-safe.
type shimCounters struct {
	InitiationsReceived   int64
	InitiationsDropped    int64
	InitiationsForwarded  int64
	InitiationsDuplicated int64
	ResponsesReceived     int64
	ResponsesDropped      int64
	ResponsesForwarded    int64
	TransportForwarded    int64
	TotalPacketsForwarded int64
}

// handshakeObservation is the complete failure-local record for one dial.
type handshakeObservation struct {
	Phase           handshakePhase
	Outcome         handshakeOutcome
	PreDeviceToDial milestoneDelta // before client construction -> dial start
	DialToHandshake time.Duration  // meaningful only when Outcome is completed
	FirstInitiation milestoneDelta
	FirstResponse   milestoneDelta
	Counters        shimCounters
}

// markFirstArrival records the first arrival time (absolute unix nanos) of each
// handshake-relevant packet class. It is first-wins, allocation-free and called
// from the shim's existing forward loop, so it adds no goroutine and no polling.
func (s *UDPFaultShim) markFirstArrival(dir PacketDirection, pktType PacketType) {
	var target *atomic.Int64
	switch {
	case dir == DirClientToServer && pktType == PacketTypeInitiation:
		target = &s.firstInitiationNanos
	case dir == DirServerToClient && pktType == PacketTypeResponse:
		target = &s.firstResponseNanos
	default:
		return
	}
	target.CompareAndSwap(0, time.Now().UnixNano())
}

// snapshotCounters reads the shim's existing deterministic counters.
func (s *UDPFaultShim) snapshotCounters() shimCounters {
	return shimCounters{
		InitiationsReceived:   s.InitiationsReceived.Load(),
		InitiationsDropped:    s.InitiationsDropped.Load(),
		InitiationsForwarded:  s.InitiationsForwarded.Load(),
		InitiationsDuplicated: s.InitiationsDuplicated.Load(),
		ResponsesReceived:     s.ResponsesReceived.Load(),
		ResponsesDropped:      s.ResponsesDropped.Load(),
		ResponsesForwarded:    s.ResponsesForwarded.Load(),
		TransportForwarded:    s.TransportForwarded.Load(),
		TotalPacketsForwarded: s.TotalPacketsForwarded.Load(),
	}
}

// parseHandshakeCompletion extracts the last successful handshake time from a
// client UAPI dump. It reads only the two last_handshake_time_* keys; every other
// line, including key material and endpoints, is ignored. A nil error with a zero
// time means "no handshake recorded yet"; an error means the state could not be
// determined and must be reported as unknown rather than as not-completed.
func parseHandshakeCompletion(uapi string) (time.Time, error) {
	var sec, nsec int64
	var haveSec bool
	for _, line := range strings.Split(uapi, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse last_handshake_time_sec: %w", err)
			}
			sec, haveSec = v, true
		case "last_handshake_time_nsec":
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse last_handshake_time_nsec: %w", err)
			}
			nsec = v
		}
	}
	if !haveSec || sec <= 0 {
		return time.Time{}, nil
	}
	return time.Unix(sec, nsec), nil
}

// readHandshakeCompletion reads the client's handshake state once. A read or parse
// failure is returned distinctly from "no handshake yet" so the caller reports
// unknown instead of claiming a negative result it did not observe.
func readHandshakeCompletion(c *HarnessClient) (time.Time, error) {
	if c == nil {
		return time.Time{}, errors.New("no client")
	}
	raw, err := c.IpcGet()
	if err != nil {
		return time.Time{}, err
	}
	return parseHandshakeCompletion(raw)
}

// applyShimObservation fills counters and the two shim-side relative milestones.
func (o *handshakeObservation) applyShimObservation(s *UDPFaultShim, dialStart time.Time) {
	if s == nil {
		return
	}
	o.Counters = s.snapshotCounters()
	origin := dialStart.UnixNano()
	if v := s.firstInitiationNanos.Load(); v > 0 {
		o.FirstInitiation = milestoneDelta{observed: true, delta: time.Duration(v - origin)}
	}
	if v := s.firstResponseNanos.Load(); v > 0 {
		o.FirstResponse = milestoneDelta{observed: true, delta: time.Duration(v - origin)}
	}
}

// observeHandshakeFailure builds the failure-local observation for one dial.
func observeHandshakeFailure(phase handshakePhase, c *HarnessClient, s *UDPFaultShim, dialStart time.Time) handshakeObservation {
	obs := handshakeObservation{Phase: phase, Outcome: handshakeOutcomeUnknown}
	obs.applyShimObservation(s, dialStart)

	at, err := readHandshakeCompletion(c)
	switch {
	case err != nil:
		obs.Outcome = handshakeOutcomeUnknown
	case at.IsZero():
		obs.Outcome = handshakeOutcomeNotCompleted
	default:
		obs.Outcome = handshakeOutcomeCompleted
		obs.DialToHandshake = at.Sub(dialStart)
	}
	return obs
}

// millis converts a duration to whole milliseconds for emission.
func millis(d time.Duration) int64 {
	return int64(d.Round(time.Millisecond) / time.Millisecond)
}

func writeMilestone(b *strings.Builder, key string, m milestoneDelta) {
	if !m.observed {
		fmt.Fprintf(b, " %s=absent", key)
		return
	}
	fmt.Fprintf(b, " %s=%d", key, millis(m.delta))
}

// String renders the observation as space-separated key=value tokens. Values are
// enum tokens, relative millisecond counts or counters only.
func (o handshakeObservation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "phase=%s outcome=%s", o.Phase, o.Outcome)
	if o.Outcome == handshakeOutcomeCompleted {
		fmt.Fprintf(&b, " dial_to_handshake_ms=%d", millis(o.DialToHandshake))
	} else {
		b.WriteString(" dial_to_handshake_ms=unknown")
	}
	writeMilestone(&b, "pre_device_to_dial_ms", o.PreDeviceToDial)
	writeMilestone(&b, "dial_to_first_initiation_ms", o.FirstInitiation)
	writeMilestone(&b, "dial_to_first_response_ms", o.FirstResponse)

	c := o.Counters
	fmt.Fprintf(&b, " counters_initiations_received=%d", c.InitiationsReceived)
	fmt.Fprintf(&b, " counters_initiations_dropped=%d", c.InitiationsDropped)
	fmt.Fprintf(&b, " counters_initiations_forwarded=%d", c.InitiationsForwarded)
	fmt.Fprintf(&b, " counters_initiations_duplicated=%d", c.InitiationsDuplicated)
	fmt.Fprintf(&b, " counters_responses_received=%d", c.ResponsesReceived)
	fmt.Fprintf(&b, " counters_responses_dropped=%d", c.ResponsesDropped)
	fmt.Fprintf(&b, " counters_responses_forwarded=%d", c.ResponsesForwarded)
	fmt.Fprintf(&b, " counters_transport_forwarded=%d", c.TransportForwarded)
	fmt.Fprintf(&b, " counters_total_packets_forwarded=%d", c.TotalPacketsForwarded)
	return b.String()
}

// handshakeObservationKeys is the closed set of keys the formatter may emit.
var handshakeObservationKeys = map[string]struct{}{
	"phase":                            {},
	"outcome":                          {},
	"dial_to_handshake_ms":             {},
	"pre_device_to_dial_ms":            {},
	"dial_to_first_initiation_ms":      {},
	"dial_to_first_response_ms":        {},
	"counters_initiations_received":    {},
	"counters_initiations_dropped":     {},
	"counters_initiations_forwarded":   {},
	"counters_initiations_duplicated":  {},
	"counters_responses_received":      {},
	"counters_responses_dropped":       {},
	"counters_responses_forwarded":     {},
	"counters_transport_forwarded":     {},
	"counters_total_packets_forwarded": {},
}

// Value grammar: a lowercase enum token of at most 16 characters, or a relative
// millisecond/count integer of at most 9 digits (|v| < 1e9, i.e. under ~11.6
// days). Uppercase, base64/hex payloads, dotted/colon addresses and absolute
// epoch seconds or nanoseconds cannot match.
var (
	obsKeyPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	obsValuePattern = regexp.MustCompile(`^(?:[a-z][a-z0-9_]{0,15}|-?[0-9]{1,9})$`)
)

// validateObservationToken accepts one key=value token and returns its key, or an
// error naming which part of the schema it violated.
func validateObservationToken(i int, tok string) (string, error) {
	key, value, ok := strings.Cut(tok, "=")
	if !ok {
		return "", fmt.Errorf("schema: token %d is not key=value", i)
	}
	if !obsKeyPattern.MatchString(key) {
		return "", fmt.Errorf("schema: token %d has a non-enum key", i)
	}
	if _, allowed := handshakeObservationKeys[key]; !allowed {
		return "", fmt.Errorf("schema: token %d key %q is not allowlisted", i, key)
	}
	if !obsValuePattern.MatchString(value) {
		return "", fmt.Errorf("schema: token %d value for key %q is not an enum token or bounded relative count", i, key)
	}
	return key, nil
}

// validateHandshakeObservation enforces the emitted schema so a future edit that
// tried to pass bytes, a key, an address or an absolute timestamp cannot pass
// unnoticed. Every token must be exactly one key=value with an allowlisted key.
func validateHandshakeObservation(line string) error {
	tokens := strings.Fields(line)
	if len(tokens) != len(handshakeObservationKeys) {
		return fmt.Errorf("schema: got %d tokens, want %d", len(tokens), len(handshakeObservationKeys))
	}
	seen := make(map[string]struct{}, len(tokens))
	for i, tok := range tokens {
		key, err := validateObservationToken(i, tok)
		if err != nil {
			return err
		}
		seen[key] = struct{}{}
	}
	if len(seen) != len(handshakeObservationKeys) {
		return fmt.Errorf("schema: %d distinct keys, want %d", len(seen), len(handshakeObservationKeys))
	}
	return nil
}

// formatDialFailureObservation builds and schema-validates the emission line for
// a dial that did not complete. It returns an error instead of the line on a
// schema violation, so a future formatter regression cannot print leak-shaped
// output through the failure log.
func formatDialFailureObservation(phase handshakePhase, c *HarnessClient, s *UDPFaultShim, preDevice, dialStart time.Time) (string, error) {
	obs := observeHandshakeFailure(phase, c, s, dialStart)
	obs.PreDeviceToDial = milestoneDelta{observed: true, delta: dialStart.Sub(preDevice)}
	line := obs.String()
	if err := validateHandshakeObservation(line); err != nil {
		return "", err
	}
	return line, nil
}

// logDialFailureObservation emits the failure-local handshake observation.
func logDialFailureObservation(t *testing.T, phase handshakePhase, c *HarnessClient, s *UDPFaultShim, preDevice, dialStart time.Time) {
	t.Helper()
	line, err := formatDialFailureObservation(phase, c, s, preDevice, dialStart)
	if err != nil {
		t.Logf("handshake observation suppressed by schema control: %v", err)
		return
	}
	t.Logf("handshake observation: %s", line)
}

// TestHandshakeObservationFormatter covers the positive formatting contract:
// only enums, relative millisecond counts and counters, with an explicit
// unknown/absent state instead of a fabricated zero.
func TestHandshakeObservationFormatter(t *testing.T) {
	t.Run("completed reference phase validates", func(t *testing.T) {
		obs := handshakeObservation{
			Phase:           phaseReference,
			Outcome:         handshakeOutcomeCompleted,
			DialToHandshake: 1132*time.Millisecond + 640*time.Microsecond,
			FirstInitiation: milestoneDelta{observed: true, delta: 43 * time.Millisecond},
			FirstResponse:   milestoneDelta{observed: true, delta: 61 * time.Millisecond},
			Counters:        shimCounters{InitiationsReceived: 1, InitiationsForwarded: 2, InitiationsDuplicated: 1, ResponsesReceived: 1, ResponsesForwarded: 1, TotalPacketsForwarded: 5},
		}
		line := obs.String()
		if err := validateHandshakeObservation(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		for _, want := range []string{"phase=ref", "outcome=completed", "dial_to_handshake_ms=1133", "dial_to_first_initiation_ms=43", "dial_to_first_response_ms=61", "counters_initiations_duplicated=1"} {
			if !strings.Contains(line, want) {
				t.Errorf("output %q missing %q", line, want)
			}
		}
	})

	t.Run("not completed reports unknown duration not zero", func(t *testing.T) {
		obs := handshakeObservation{Phase: phaseReference, Outcome: handshakeOutcomeNotCompleted}
		line := obs.String()
		if err := validateHandshakeObservation(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		if !strings.Contains(line, "outcome=not_completed") || !strings.Contains(line, "dial_to_handshake_ms=unknown") {
			t.Fatalf("output %q must report not_completed with unknown duration", line)
		}
		if strings.Contains(line, "dial_to_handshake_ms=0") {
			t.Fatalf("output %q fabricated a zero handshake duration", line)
		}
	})

	t.Run("unreadable outcome stays unknown", func(t *testing.T) {
		obs := handshakeObservation{Phase: phaseSubject}
		line := obs.String()
		if err := validateHandshakeObservation(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		if !strings.Contains(line, "phase=sub") || !strings.Contains(line, "outcome=unknown") || !strings.Contains(line, "dial_to_handshake_ms=unknown") {
			t.Fatalf("output %q must report unknown without a fabricated outcome", line)
		}
	})

	t.Run("unobserved milestones are absent and negative deltas stay visible", func(t *testing.T) {
		obs := handshakeObservation{Phase: phaseReference, Outcome: handshakeOutcomeNotCompleted}
		line := obs.String()
		if !strings.Contains(line, "dial_to_first_initiation_ms=absent") || !strings.Contains(line, "dial_to_first_response_ms=absent") {
			t.Fatalf("output %q must report absent milestones", line)
		}
		obs.FirstInitiation = milestoneDelta{observed: true, delta: -3 * time.Millisecond}
		line = obs.String()
		if err := validateHandshakeObservation(line); err != nil {
			t.Fatalf("validate %q: %v", line, err)
		}
		if !strings.Contains(line, "dial_to_first_initiation_ms=-3") {
			t.Fatalf("output %q must keep a negative delta visible", line)
		}
	})

	t.Run("bounded counter maximum still validates", func(t *testing.T) {
		obs := handshakeObservation{Phase: phaseSubject, Outcome: handshakeOutcomeNotCompleted}
		obs.Counters.TotalPacketsForwarded = 999999999
		if err := validateHandshakeObservation(obs.String()); err != nil {
			t.Fatalf("validate bounded counter: %v", err)
		}
	})
}

// TestHandshakeObservationPrivacyControls is the negative half: the validator must
// reject secret, private and payload-shaped values, the observation type must be
// structurally incapable of carrying free text, and the real emission path must
// report unknown rather than fabricate a completed handshake.
func TestHandshakeObservationPrivacyControls(t *testing.T) {
	t.Run("schema rejects leak-shaped values", func(t *testing.T) {
		base := handshakeObservation{Phase: phaseReference, Outcome: handshakeOutcomeNotCompleted}.String()
		cases := map[string]string{
			"uppercase base64 key":   strings.Replace(base, "outcome=not_completed", "outcome=QWxhZGRpbjpvcGVuIHNlc2FtZQ==", 1),
			"long lowercase hex key": strings.Replace(base, "outcome=not_completed", "outcome="+strings.Repeat("ab", 32), 1),
			"private ipv4 endpoint":  strings.Replace(base, "outcome=not_completed", "outcome=192.0.2.55:51820", 1),
			"test payload":           strings.Replace(base, "outcome=not_completed", "outcome=diff-duplicate-initiation-data", 1),
			"absolute epoch seconds": strings.Replace(base, "outcome=not_completed", "outcome=1794000000", 1),
			"absolute epoch nanos":   strings.Replace(base, "outcome=not_completed", "outcome=1794000000000000000", 1),
			"bare token":             base + " deadbeef",
			"non allowlisted key":    strings.Replace(base, "outcome=not_completed", "private_key=abc", 1),
		}
		for name, line := range cases {
			if err := validateHandshakeObservation(line); err == nil {
				t.Errorf("%s: validator accepted leak-shaped output %q", name, line)
			}
		}
	})

	t.Run("observation type carries no string or byte field", func(t *testing.T) {
		assertNoStringLikeFields(t, reflect.TypeOf(handshakeObservation{}), "handshakeObservation")
	})

	t.Run("emission path reports unknown for nil inputs", func(t *testing.T) {
		// Fully offline: no device, no socket. Proves the real emission path is
		// nil-safe and reports unknown rather than fabricating a completed
		// handshake or a zero duration.
		line, err := formatDialFailureObservation(phaseReference, nil, nil, time.Now().Add(-20*time.Millisecond), time.Now())
		if err != nil {
			t.Fatalf("format for nil inputs: %v", err)
		}
		if !strings.Contains(line, "outcome=unknown") || !strings.Contains(line, "dial_to_handshake_ms=unknown") {
			t.Fatalf("nil-input line %q must report unknown", line)
		}
		if !strings.Contains(line, "pre_device_to_dial_ms=20") {
			t.Fatalf("nil-input line %q must still carry the pre-device milestone", line)
		}
		if strings.Contains(line, "dial_to_first_initiation_ms=0") || strings.Contains(line, "dial_to_first_response_ms=0") {
			t.Fatalf("nil-input line %q fabricated a shim milestone", line)
		}
	})
}

// assertNoStringLikeFields fails if t or any reachable struct field is a string,
// byte slice or byte array, which are the only shapes that could carry keys,
// packet bytes or endpoint text.
func assertNoStringLikeFields(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	switch typ.Kind() {
	case reflect.String:
		t.Fatalf("%s is a string: free text could carry secrets", path)
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s is a byte sequence: packet bytes or keys could be carried", path)
		}
	case reflect.Pointer:
		assertNoStringLikeFields(t, typ.Elem(), path+"*")
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			assertNoStringLikeFields(t, f.Type, path+"."+f.Name)
		}
	}
}

// TestParseHandshakeCompletion covers the pure UAPI parsing used on the failure
// path, including an unrelated key-material line that must be ignored and a
// malformed value that must be reported as unknown rather than not-completed.
func TestParseHandshakeCompletion(t *testing.T) {
	t.Run("parses sec and nsec and ignores key material", func(t *testing.T) {
		uapi := strings.Join([]string{
			"private_key=00000000000000000000000000000000000000000000000000000000000000ff",
			"listen_port=51820",
			"public_key=1111111111111111111111111111111111111111111111111111111111111111",
			"endpoint=192.0.2.55:51820",
			"last_handshake_time_sec=1794000000",
			"last_handshake_time_nsec=250000000",
			"tx_bytes=1280",
			"rx_bytes=1280",
		}, "\n")
		at, err := parseHandshakeCompletion(uapi)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		want := time.Unix(1794000000, 250000000)
		if !at.Equal(want) {
			t.Fatalf("got %v, want %v", at, want)
		}
	})

	t.Run("zero or missing handshake is not completed", func(t *testing.T) {
		for name, uapi := range map[string]string{
			"zero sec": "last_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			"no field": "private_key=ff\nlisten_port=51820\n",
			"empty":    "",
		} {
			at, err := parseHandshakeCompletion(uapi)
			if err != nil || !at.IsZero() {
				t.Errorf("%s: got (%v,%v), want not completed with no error", name, at, err)
			}
		}
	})

	t.Run("malformed value is an error not a negative observation", func(t *testing.T) {
		for name, uapi := range map[string]string{
			"bad sec":  "last_handshake_time_sec=not-a-number\n",
			"bad nsec": "last_handshake_time_sec=1794000000\nlast_handshake_time_nsec=oops\n",
		} {
			if _, err := parseHandshakeCompletion(uapi); err == nil {
				t.Errorf("%s: malformed state was accepted as a determined result", name)
			}
		}
	})
}

// TestShimFirstArrivalMilestones is an offline control for the shim-side capture
// path: it drives markFirstArrival directly (no socket, no forward loop) and
// checks first-wins semantics, direction/type filtering and the counters snapshot.
func TestShimFirstArrivalMilestones(t *testing.T) {
	shim := &UDPFaultShim{}

	origin := time.Now()
	shim.markFirstArrival(DirClientToServer, PacketTypeInitiation)
	first := shim.firstInitiationNanos.Load()
	if first <= 0 {
		t.Fatal("first initiation was not recorded")
	}

	// A later initiation must not move the first-arrival mark.
	time.Sleep(time.Millisecond)
	shim.markFirstArrival(DirClientToServer, PacketTypeInitiation)
	if got := shim.firstInitiationNanos.Load(); got != first {
		t.Fatalf("first-arrival marker moved: got %d, want %d", got, first)
	}

	// Wrong direction/type must not populate the response marker.
	shim.markFirstArrival(DirClientToServer, PacketTypeResponse)
	shim.markFirstArrival(DirServerToClient, PacketTypeInitiation)
	shim.markFirstArrival(DirServerToClient, PacketTypeTransport)
	if v := shim.firstResponseNanos.Load(); v != 0 {
		t.Fatalf("response marker set by a non-response packet: %d", v)
	}

	shim.markFirstArrival(DirServerToClient, PacketTypeResponse)
	if v := shim.firstResponseNanos.Load(); v <= 0 {
		t.Fatal("first response was not recorded")
	}

	obs := handshakeObservation{Phase: phaseReference, Outcome: handshakeOutcomeNotCompleted}
	obs.applyShimObservation(shim, origin)
	if !obs.FirstInitiation.observed || !obs.FirstResponse.observed {
		t.Fatalf("milestones not surfaced: %+v %+v", obs.FirstInitiation, obs.FirstResponse)
	}
	if obs.FirstInitiation.delta < 0 || obs.FirstResponse.delta < 0 {
		t.Fatalf("relative deltas must not be negative for arrivals after dial start: %+v %+v", obs.FirstInitiation, obs.FirstResponse)
	}
	if obs.FirstResponse.delta < obs.FirstInitiation.delta {
		t.Fatalf("response (%v) predates initiation (%v)", obs.FirstResponse.delta, obs.FirstInitiation.delta)
	}

	// A shim with no observed traffic must report absent, never zero.
	empty := handshakeObservation{Phase: phaseSubject, Outcome: handshakeOutcomeUnknown}
	empty.applyShimObservation(&UDPFaultShim{}, origin)
	if empty.FirstInitiation.observed || empty.FirstResponse.observed {
		t.Fatalf("unobserved milestones reported as observed: %+v %+v", empty.FirstInitiation, empty.FirstResponse)
	}
	if err := validateHandshakeObservation(empty.String()); err != nil {
		t.Fatalf("unobserved-line schema: %v", err)
	}
}
