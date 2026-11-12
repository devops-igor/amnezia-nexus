//go:build with_utls

package handlers

// Unit coverage for the parsers the consumer capture depends on.
//
// The consumer tests themselves drive the whole handler flow and are expected to run in the
// feature CI, not here. These are different: they are pure functions over a fixed UAPI string,
// so they can be executed locally and they pin the two behaviours a wrong parser would silently
// turn into a green-but-meaningless assertion:
//
//   - a key the engine OMITS is the engine's zero default, not a missing observation, because
//     the engine prints a knob only when it is non-zero;
//   - "present" means present, so a zero counter is never read as traffic.

import (
	"errors"
	"strings"
	"testing"
)

// awgConsumerSampleIPC is a fixed dump in the shape the engine actually produces.
//
// It is a literal on purpose: it is not produced by the code under test, so agreement between
// the parser and this fixture is evidence about the parser rather than about itself. The
// fields mirror what `Device.IpcGet` emits - device knobs first (only non-zero ones), then one
// peer section - with values chosen so every branch of the parser is exercised.
const awgConsumerSampleIPC = `private_key=<redacted>
listen_port=51820
jc=1
jmin=10
jmax=20
s1=15
s2=40
h1=1020325451
h2=3288052141
h3=3
h4=4
i1=<r 2><b 0x0200>
public_key=<redacted>
protocol_version=1
endpoint=127.0.0.1:51820
last_handshake_time_sec=1700000000
last_handshake_time_nsec=123
tx_bytes=148
rx_bytes=296
`

// TestAWGDialectComparisonRecognisesTheDeployedDialect pins the positive: a device reporting
// exactly the deployed values matches on every key.
func TestAWGDialectComparisonRecognisesTheDeployedDialect(t *testing.T) {
	// Deployed dialect is the fixture's identity dialect, so build a dump that reports it.
	// Padding and junk keys are omitted here because the engine omits zero values - the parser
	// must still call them a match against the deployed zero.
	ipc := strings.Join([]string{
		"private_key=<redacted>",
		"listen_port=51820",
		"h1=1",
		"h2=2",
		"h3=3",
		"h4=4",
		"public_key=<redacted>",
		"tx_bytes=148",
		"rx_bytes=296",
		"last_handshake_time_sec=1700000000",
		"",
	}, "\n")

	report := compareAWGDialect(ipc)
	if !report.allMatch() {
		t.Fatalf("the deployed dialect was reported as a mismatch: %v (absent=%v)",
			report.mismatched(), report.missing)
	}
	if len(report.mismatched()) != 0 {
		t.Fatalf("mismatched() = %v, want none", report.mismatched())
	}
}

// TestAWGDialectComparisonNamesADivergence pins the negative half: a device configured with
// production's default dialect is reported as a mismatch on the keys that differ, and the
// omitted zero keys are listed as absent rather than as failures.
func TestAWGDialectComparisonNamesADivergence(t *testing.T) {
	// This is what the engine reports when the device received no parameters: jc defaults to
	// 1 and the padding keys keep their defaults, while the fixture deployed jc=0 and no
	// padding.
	report := compareAWGDialect(awgConsumerSampleIPC)

	if report.allMatch() {
		t.Fatal("a device configured with production's default dialect matched the identity dialect, " +
			"so this comparison cannot detect the divergence it exists for")
	}
	mismatched := report.mismatched()
	// Every non-zero knob in the sample differs from the deployed identity dialect.
	for _, want := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2"} {
		if !containsString(mismatched, want) {
			t.Errorf("%q differs between the device and the deployed dialect but was not reported; "+
				"mismatched=%v", want, mismatched)
		}
	}
	// h3=3 and h4=4 are the only knobs identical on both sides.
	for _, want := range []string{"h3", "h4"} {
		if containsString(mismatched, want) {
			t.Errorf("%q is identical in both dialects but was reported as a mismatch "+
				"(mismatched=%v)", want, mismatched)
		}
	}
	// s3 and s4 are zero on the device, so the engine omits them and the parser reads them as
	// the deployed zero rather than as a missing observation.
	if !containsString(report.missing, "s3") || !containsString(report.missing, "s4") {
		t.Fatalf("the omissible zero knobs s3/s4 were not reported as absent: %v", report.missing)
	}
}

// TestAWGDeviceCountersReportPresenceNotValues pins the counter reader: it distinguishes "sent
// something" from "sent nothing", and it treats a completed handshake as an observation.
func TestAWGDeviceCountersReportPresenceNotValues(t *testing.T) {
	got := readAWGDeviceCounters(awgConsumerSampleIPC)
	if !got.txPositive {
		t.Error("tx_bytes=148 was not reported as transmitted traffic")
	}
	if !got.rxPositive {
		t.Error("rx_bytes=296 was not reported as received traffic")
	}
	if !got.handshakeObserved {
		t.Error("last_handshake_time_sec=1700000000 was not reported as a completed handshake")
	}
	if !got.i1Present {
		t.Error("i1 was configured but was not reported as present")
	}

	// A fresh device sends nothing and has no handshake, and the engine omits i1 when unset.
	silent := readAWGDeviceCounters(strings.Join([]string{
		"private_key=<redacted>",
		"listen_port=51820",
		"public_key=<redacted>",
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=0",
		"rx_bytes=0",
		"",
	}, "\n"))
	if silent.txPositive || silent.rxPositive || silent.handshakeObserved || silent.i1Present {
		t.Fatalf("a device that has exchanged nothing was reported as active: %+v", silent)
	}
}

// TestAWGConsumerDiagnosisNamesTheBoundary pins the decision table, so a remote failure's log
// line names the boundary rather than only reporting that something failed.
func TestAWGConsumerDiagnosisNamesTheBoundary(t *testing.T) {
	healthy := awgConsumerObservation{
		captured:          true,
		deviceFound:       true,
		deviceIsAWGDevice: true,
		endpointMatches:   true,
		tunnelEndpointOK:  true,
		dialect:           awgDialectReport{match: allDialectKeysMatch()},
		counters: awgDeviceCounters{
			txPositive: true, rxPositive: true, handshakeObserved: true, i1Present: true,
		},
	}

	cases := []struct {
		name    string
		mutate  func(o *awgConsumerObservation)
		wantSub string
	}{
		{
			name:    "no device",
			mutate:  func(o *awgConsumerObservation) { o.deviceFound = false },
			wantSub: "no backend device was attached",
		},
		{
			name:    "wrong device type",
			mutate:  func(o *awgConsumerObservation) { o.deviceIsAWGDevice = false },
			wantSub: "not the production AWG device",
		},
		{
			name:    "endpoint diverged",
			mutate:  func(o *awgConsumerObservation) { o.endpointMatches = false },
			wantSub: "endpoint differs",
		},
		{
			name: "dialect diverged",
			mutate: func(o *awgConsumerObservation) {
				o.dialect = awgDialectReport{match: map[string]bool{"jc": false}}
			},
			wantSub: "dialect differs",
		},
		{
			name:    "preamble absent",
			mutate:  func(o *awgConsumerObservation) { o.counters.i1Present = false },
			wantSub: "no data-plane preamble",
		},
		{
			name: "nothing transmitted",
			mutate: func(o *awgConsumerObservation) {
				o.counters.txPositive = false
				o.counters.rxPositive = false
				o.counters.handshakeObserved = false
			},
			wantSub: "transmitted nothing",
		},
		{
			name: "handshake dropped",
			mutate: func(o *awgConsumerObservation) {
				o.counters.rxPositive = false
				o.counters.handshakeObserved = false
			},
			wantSub: "no handshake completed",
		},
		{
			name:    "transport unanswered",
			mutate:  func(o *awgConsumerObservation) { o.counters.rxPositive = false },
			wantSub: "nothing came back",
		},
		{
			name: "payload unanswered",
			mutate: func(o *awgConsumerObservation) {
				o.canaryErr = errors.New("canary probe timed out")
			},
			wantSub: "payload was not answered",
		},
	}

	if got := healthy.diagnosis(); got != "every observed boundary is healthy" {
		t.Fatalf("a fully healthy observation was diagnosed as %q", got)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := healthy
			tc.mutate(&o)
			got := o.diagnosis()
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("diagnosis() = %q, want it to name %q", got, tc.wantSub)
			}
		})
	}
}

// allDialectKeysMatch builds the "everything agrees" map the healthy observation needs.
func allDialectKeysMatch() map[string]bool {
	out := make(map[string]bool, len(awgConsumerDialectKeys))
	for _, k := range awgConsumerDialectKeys {
		out[k] = true
	}
	return out
}

// containsString reports membership for the small slices these tests build.
func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
