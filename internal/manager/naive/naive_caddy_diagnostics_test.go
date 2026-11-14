package naive

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Bounds for the stderr digest. They exist so a pathological child cannot turn a
// failed test into an unbounded log dump.
const (
	caddyDigestScanLimit  = 1 << 20
	caddyDigestEventLimit = 32
)

// caddyLogFields is the bounded subset of a Caddy JSON log record the digest reads.
// Every other field is ignored, which is what keeps the report privacy-safe: it
// cannot echo a field it never decodes.
type caddyLogFields struct {
	TS         float64 `json:"ts"`
	Logger     string  `json:"logger"`
	Msg        string  `json:"msg"`
	Error      string  `json:"error"`
	Issuer     string  `json:"issuer"`
	NumChoices *int    `json:"num_choices"`
	CacheSize  *int    `json:"cache_size"`
}

// caddyDiagnosticEvent is one whitelisted observation with its offset from the
// first timestamped log line of the child process.
type caddyDiagnosticEvent struct {
	offsetMS int64
	tag      string
	detail   string
}

// reportCaddyDiagnostics logs a privacy-safe digest of the Caddy child's captured
// stderr. Call it on a failure path only: the digest is deliberately narrow, and it
// exists to explain why the child could not complete a TLS obligation.
//
// It never prints raw log text. Certificate identifiers, certificate subjects,
// request headers (including Proxy-Authorization and forwarded credentials), file
// and key paths, key material, CSR bodies, addresses and arbitrary error strings
// are all reduced to fixed classifications.
func reportCaddyDiagnostics(t *testing.T, label string, buf *safeBuffer) {
	t.Helper()
	if buf == nil {
		t.Logf("CADDY_DIAGNOSTICS[%s]: no stderr buffer", label)
		return
	}
	t.Logf("CADDY_DIAGNOSTICS[%s]:\n%s", label, caddyStderrDigest(buf.String()))
}

// waitForCaddyStderrSettled blocks until the child stops appending to the buffer,
// or the deadline expires.
//
// Caddy writes its final record for a rejected ClientHello asynchronously, so a
// report taken the instant an assertion fails can be one line short of the record
// that explains it. This waits for a quiet period instead of a fixed sleep: it
// returns as soon as output has stopped, and it never fails the test on timeout
// because the digest is still useful without the last line.
func waitForCaddyStderrSettled(buf *safeBuffer, quiet, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	last := -1
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		n := buf.Len()
		if n != last {
			last = n
			stableSince = time.Now()
		} else if time.Since(stableSince) >= quiet {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// caddyStderrDigest reduces the child's raw stderr to whitelisted certificate
// acquisition, cache, certificate-selection and handshake facts with timings.
//
// The returned text contains only: counters, booleans, fixed classification tags,
// fixed error classes and integer millisecond offsets.
func caddyStderrDigest(raw string) string {
	truncated := false
	if len(raw) > caddyDigestScanLimit {
		raw = raw[:caddyDigestScanLimit]
		truncated = true
	}

	var (
		events     []caddyDiagnosticEvent
		lines      int
		unparsed   int
		baseTS     float64
		lastTS     float64
		haveBase   bool
		suppressed int
		summary    caddyDigestSummary
	)

	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines++

		var f caddyLogFields
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			unparsed++
			continue
		}

		if f.TS > 0 {
			if !haveBase {
				baseTS, haveBase = f.TS, true
			}
			lastTS = f.TS
		}

		tag, detail, ok := classifyCaddyLog(f)
		if !ok {
			continue
		}
		summary.observe(tag)

		if len(events) >= caddyDigestEventLimit {
			suppressed++
			continue
		}
		events = append(events, caddyDiagnosticEvent{
			offsetMS: caddyOffsetMS(baseTS, haveBase, f.TS),
			tag:      tag,
			detail:   detail,
		})
	}

	var b strings.Builder
	if raw == "" {
		b.WriteString("empty=true")
	} else {
		fmt.Fprintf(&b, "bytes=%d lines=%d unparsed=%d events=%d/%d suppressed=%d",
			len(raw), lines, unparsed, len(events), caddyDigestEventLimit, suppressed)
	}
	fmt.Fprintf(&b, " truncated=%t", truncated)
	if haveBase && lastTS >= baseTS {
		fmt.Fprintf(&b, " span_ms=%d", int64((lastTS-baseTS)*1000))
	}
	b.WriteString("\n")
	b.WriteString(summary.String())
	if len(events) > 0 {
		b.WriteString("\n  timeline:")
		for _, e := range events {
			fmt.Fprintf(&b, "\n    +%dms %s", e.offsetMS, e.tag)
			if e.detail != "" {
				fmt.Fprintf(&b, " %s", e.detail)
			}
		}
	}
	return b.String()
}

// caddyOffsetMS converts a log timestamp into an offset from the first one seen.
func caddyOffsetMS(base float64, haveBase bool, ts float64) int64 {
	if !haveBase || ts <= 0 || ts < base {
		return -1
	}
	return int64((ts - base) * 1000)
}

// caddyDigestSummary holds the presence flags that answer the actual question:
// did a certificate ever exist, and did a handshake arrive before it did.
type caddyDigestSummary struct {
	certObtained      bool
	cacheAdded        bool
	acquisitionErrors int
	selectNoMatch     int
	handshakeErrors   int
	trustInstall      int
}

func (s *caddyDigestSummary) observe(tag string) {
	switch tag {
	case "acquisition.obtained":
		s.certObtained = true
	case "cache.added":
		s.cacheAdded = true
	case "acquisition.error":
		s.acquisitionErrors++
	case "select.no-match":
		s.selectNoMatch++
	case "handshake.error":
		s.handshakeErrors++
	case "trust.install-attempted", "trust.install-failed":
		s.trustInstall++
	}
}

func (s caddyDigestSummary) String() string {
	return fmt.Sprintf("  cert_obtained=%t cache_added=%t acquisition_errors=%d select_no_match=%d handshake_errors=%d trust_install_events=%d",
		s.certObtained, s.cacheAdded, s.acquisitionErrors, s.selectNoMatch, s.handshakeErrors, s.trustInstall)
}

// caddyRule is one allowlist entry: a log record matches when its logger is the
// expected one and its message is either exactly `msg` or starts with `msgPrefix`.
// The tag is fixed text, and detail derives from whitelisted scalar fields only.
type caddyRule struct {
	logger    string
	msg       string
	msgPrefix string
	tag       string
	detail    func(caddyLogFields) string
}

// caddyRules is the complete allowlist. A record that matches no rule is dropped,
// so adding a Caddy log message to the report requires adding it here deliberately.
// Reading the list top to bottom is the whole privacy review.
var caddyRules = []caddyRule{
	{logger: "tls.obtain", msg: "acquiring lock", tag: "acquisition.lock-wait"},
	{logger: "tls.obtain", msg: "lock acquired", tag: "acquisition.lock-acquired"},
	{logger: "tls.obtain", msg: "obtaining certificate", tag: "acquisition.start"},
	{logger: "tls.obtain", msgPrefix: "trying issuer", tag: "acquisition.issuer-attempt",
		detail: func(f caddyLogFields) string { return safeCaddyIssuer(f.Issuer) }},
	{logger: "tls.obtain", msg: "certificate obtained successfully", tag: "acquisition.obtained",
		detail: func(f caddyLogFields) string { return safeCaddyIssuer(f.Issuer) }},
	{logger: "tls.obtain", msg: "releasing lock", tag: "acquisition.lock-released"},
	{logger: "tls.obtain", msg: "error", tag: "acquisition.error",
		detail: func(f caddyLogFields) string { return classifyCaddyErrorText(f.Error) }},

	{logger: "tls.cache", msg: "added certificate to cache", tag: "cache.added",
		detail: func(f caddyLogFields) string { return caddyCountDetail("cache_size", f.CacheSize) }},
	{logger: "tls.cache.maintenance", msg: "started background certificate maintenance", tag: "cache.maintenance-started"},

	{logger: "tls.handshake", msg: "no matching certificates and no custom selection logic", tag: "select.no-match"},
	{logger: "tls.handshake", msg: "choosing certificate", tag: "select.choose",
		detail: func(f caddyLogFields) string { return caddyCountDetail("choices", f.NumChoices) }},
	{logger: "tls.handshake", msg: "default certificate selection results", tag: "select.default-result"},
	{logger: "tls.handshake", msg: "matched certificate in cache", tag: "select.cache-hit"},
	{logger: "tls.handshake", msg: "fell back to default certificate", tag: "select.default-fallback"},

	{logger: "http", msg: "server running", tag: "server.running"},
	{logger: "http", msg: "starting server loop", tag: "server.listen"},

	{logger: "pki.ca.local", msgPrefix: "root certificate trust store installation disabled", tag: "trust.install-disabled"},
	{logger: "pki.ca.local", msgPrefix: "installing root certificate", tag: "trust.install-attempted"},
	{logger: "pki.ca.local", msgPrefix: "failed to install root certificate", tag: "trust.install-failed",
		detail: func(f caddyLogFields) string { return classifyCaddyErrorText(f.Error) }},

	{logger: "http.stdlib", msgPrefix: "http: TLS handshake error", tag: "handshake.error",
		detail: func(f caddyLogFields) string { return classifyCaddyErrorText(f.Msg) }},
}

// classifyCaddyLog maps one log record to a fixed tag and fixed detail string.
// Anything not explicitly whitelisted is dropped, which is the allowlist that
// makes the report safe to print into CI output.
func classifyCaddyLog(f caddyLogFields) (tag, detail string, ok bool) {
	for _, rule := range caddyRules {
		if f.Logger != rule.logger {
			continue
		}
		if rule.msg != "" && f.Msg != rule.msg {
			continue
		}
		if rule.msgPrefix != "" && !strings.HasPrefix(f.Msg, rule.msgPrefix) {
			continue
		}
		if rule.detail != nil {
			detail = rule.detail(f)
		}
		return rule.tag, detail, true
	}
	return "", "", false
}

// safeCaddyIssuer passes through only the small set of issuer keys Caddy uses.
// Anything else is reported as a fixed placeholder rather than echoed.
func safeCaddyIssuer(issuer string) string {
	switch issuer {
	case "local", "acme", "zerossl", "internal":
		return "issuer=" + issuer
	}
	return "issuer=other"
}

// caddyCountDetail renders an optional integer field as a fixed key=value pair.
func caddyCountDetail(key string, v *int) string {
	if v == nil {
		return ""
	}
	return key + "=" + strconv.Itoa(*v)
}

// classifyCaddyErrorText reduces arbitrary error text to a fixed class. The text
// itself is never returned, because it routinely carries filesystem paths,
// addresses and other details that must not reach CI output.
func classifyCaddyErrorText(text string) string {
	if text == "" {
		return "class=unspecified"
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "permission denied"):
		return "class=permission-denied"
	case strings.Contains(lower, "connection refused"):
		return "class=connection-refused"
	case strings.Contains(lower, "no such file"):
		return "class=missing-file"
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return "class=timeout"
	case strings.Contains(lower, "no certificate"):
		return "class=no-certificate"
	case strings.Contains(lower, "protocol version") || strings.Contains(lower, "unsupported versions"):
		return "class=protocol-version"
	case strings.Contains(lower, "unrecognized name") || strings.Contains(lower, "unknown sni"):
		return "class=unrecognized-name"
	case strings.Contains(lower, "lock"):
		return "class=lock-conflict"
	case strings.Contains(lower, "eof"):
		return "class=eof"
	case strings.Contains(lower, "trust") || strings.Contains(lower, "sudo"):
		return "class=trust-install"
	}
	return "class=unclassified"
}

// TestCaddyDiagnosticsHelperProcess is not a real test: it is the controlled
// failing fixture the evidence test below runs in a child process. It fails on
// purpose so the failure-report path is exercised for real.
func TestCaddyDiagnosticsHelperProcess(t *testing.T) {
	if os.Getenv("CADDY_DIAGNOSTICS_HELPER") != "1" {
		t.Skip("helper process only")
	}

	var stderr safeBuffer
	_, _ = stderr.Write([]byte(hostileCaddyStderrFixture()))

	reportCaddyDiagnostics(t, "controlled-fixture", &stderr)
	t.Fatalf("controlled fixture failure: exercising the diagnostic failure path")
}

// hostileCaddyFixtureKey pems are assembled from parts rather than written as one
// literal, so this source file never itself contains a token that a secret
// scanner would (correctly) flag as key material.
var (
	hostileCaddyPEMBegin = "-----BEGIN " + "PRIVATE" + " KEY-----"
	hostileCaddyKeyToken = "HOSTILE_KEY_" + "b3c7"
)

// hostileCaddyStderrFixture mixes whitelisted Caddy records with material that
// must never appear in a failure report.
func hostileCaddyStderrFixture() string {
	lines := []string{
		`{"level":"info","ts":1794274918.5548,"logger":"http","msg":"server running"}`,
		`{"level":"info","ts":1794274918.5600,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"HOSTILE_IDENTIFIER_2f9a"}`,
		`{"level":"debug","ts":1794274918.5601,"logger":"tls.obtain","msg":"trying issuer 1/1","issuer":"local"}`,
		`{"level":"error","ts":1794274918.5700,"logger":"tls.obtain","msg":"error","identifier":"HOSTILE_IDENTIFIER_2f9a","error":"permission denied: /hostile/local/path/HOSTILE_PATH_7c1b"}`,
		`{"level":"debug","ts":1794274918.5750,"logger":"tls.handshake","msg":"no matching certificates and no custom selection logic","identifier":"HOSTILE_IDENTIFIER_2f9a"}`,
		`{"level":"debug","ts":1794274918.5755,"logger":"http.stdlib","msg":"http: TLS handshake error from 198.51.100.7:51234: EOF HOSTILE_HANDSHAKE_4d0e"}`,
		`{"level":"debug","ts":1794274918.5760,"logger":"http","msg":"handled request","request":{"headers":{"Proxy-Authorization":["Basic HOSTILE_CREDENTIAL_8b3d"]},"remote_ip":"198.51.100.7"}}`,
		`{"level":"debug","ts":1794274918.5765,"logger":"tls","msg":"event","data":{"csr_pem":"HOSTILE_CSR_b64_11aa","private_key_path":"/hostile/keys/HOSTILE_KEYPATH_5e2f"}}`,
		"plain text startup error: " + hostileCaddyPEMBegin + " " + hostileCaddyKeyToken + " /hostile/plain/HOSTILE_PATH_9d4a",
		`{"level":"info","ts":1794274918.5770,"logger":"pki.ca.local","msg":"root certificate trust store installation disabled; unconfigured clients may show warnings","path":"storage:pki/authorities/local/root.crt"}`,
	}
	return strings.Join(lines, "\n")
}

// hostileCaddyMarkers are the substrings the digest must never reproduce. Every
// one of them is present in hostileCaddyStderrFixture, so a leak assertion cannot
// pass vacuously.
var hostileCaddyMarkers = []string{
	"HOSTILE_IDENTIFIER_2f9a",
	"HOSTILE_PATH_7c1b",
	"HOSTILE_HANDSHAKE_4d0e",
	"HOSTILE_CREDENTIAL_8b3d",
	"HOSTILE_CSR_b64_11aa",
	"HOSTILE_KEYPATH_5e2f",
	hostileCaddyKeyToken,
	"HOSTILE_PATH_9d4a",
	"198.51.100.7",
	hostileCaddyPEMBegin,
	"Proxy-Authorization",
	"/hostile/",
}

// TestCaddyStderrDigestWhitelistsFacts proves the fixture carries every hostile
// marker (so the leak assertions cannot pass vacuously) and that the digest reports
// the diagnostic facts while reproducing none of that material.
func TestCaddyStderrDigestWhitelistsFacts(t *testing.T) {
	fixture := hostileCaddyStderrFixture()
	for _, marker := range hostileCaddyMarkers {
		if !strings.Contains(fixture, marker) {
			t.Fatalf("fixture is missing marker %q; its leak assertion would be vacuous", marker)
		}
	}

	digest := caddyStderrDigest(fixture)
	for _, marker := range hostileCaddyMarkers {
		if strings.Contains(digest, marker) {
			t.Errorf("digest leaked %q\n--- digest ---\n%s", marker, digest)
		}
	}

	for _, want := range []string{
		"server.running",
		"acquisition.start",
		"acquisition.issuer-attempt issuer=local",
		"acquisition.error class=permission-denied",
		"select.no-match",
		"handshake.error class=eof",
		"trust.install-disabled",
		"cert_obtained=false",
		"acquisition_errors=1",
		"select_no_match=1",
		"handshake_errors=1",
	} {
		if !strings.Contains(digest, want) {
			t.Errorf("digest missing %q\n--- digest ---\n%s", want, digest)
		}
	}
}

// TestCaddyStderrDigestDistinguishesMissingCertificate pins the one distinction the
// CI incident actually needs: a ClientHello rejected because no certificate was
// available must not look like a healthy child.
func TestCaddyStderrDigestDistinguishesMissingCertificate(t *testing.T) {
	// Certificate issuance fails, then a handshake is rejected for want of a
	// certificate. This is the shape the incident hypothesis predicts.
	missing := strings.Join([]string{
		`{"level":"info","ts":1000.000,"logger":"http","msg":"server running"}`,
		`{"level":"info","ts":1000.100,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"localhost"}`,
		`{"level":"error","ts":1000.200,"logger":"tls.obtain","msg":"error","error":"saving root certificate: mkdir /data/caddy: permission denied"}`,
		`{"level":"debug","ts":1000.300,"logger":"tls.handshake","msg":"no matching certificates and no custom selection logic","identifier":"localhost"}`,
		`{"level":"debug","ts":1000.310,"logger":"http.stdlib","msg":"http: TLS handshake error from 127.0.0.1:5: tls: no certificates configured"}`,
	}, "\n")

	got := caddyStderrDigest(missing)
	for _, want := range []string{
		"cert_obtained=false",
		"cache_added=false",
		"acquisition_errors=1",
		"acquisition.error class=permission-denied",
		"handshake.error class=no-certificate",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing-certificate digest should contain %q\n--- digest ---\n%s", want, got)
		}
	}

	// The healthy child must be clearly distinguishable from that.
	healthy := caddyStderrDigest(strings.Join([]string{
		`{"level":"info","ts":1000.000,"logger":"http","msg":"server running"}`,
		`{"level":"info","ts":1000.100,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"localhost"}`,
		`{"level":"info","ts":1000.300,"logger":"tls.obtain","msg":"certificate obtained successfully","issuer":"local"}`,
		`{"level":"debug","ts":1000.310,"logger":"tls.cache","msg":"added certificate to cache","cache_size":1}`,
	}, "\n"))
	for _, want := range []string{"cert_obtained=true", "cache_added=true", "acquisition_errors=0"} {
		if !strings.Contains(healthy, want) {
			t.Errorf("healthy digest should contain %q\n--- digest ---\n%s", want, healthy)
		}
	}

	// The decisive signal: the two must differ on the certificate-availability
	// facts, which is what a reader of the CI log needs.
	if !strings.Contains(got, "cert_obtained=false") || !strings.Contains(healthy, "cert_obtained=true") {
		t.Fatal("digest fails to separate missing-certificate from healthy")
	}
}

// TestCaddyStderrDigestBoundsAndEdgeCases pins the bounded/edge behaviour.
func TestCaddyStderrDigestBoundsAndEdgeCases(t *testing.T) {
	if got := caddyStderrDigest(""); !strings.Contains(got, "empty=true") {
		t.Errorf("empty input should report empty=true, got %q", got)
	}

	// Non-JSON output must be counted, never echoed.
	got := caddyStderrDigest("Error: adapting config using caddyfile: /home/someone/private")
	if !strings.Contains(got, "unparsed=1") || !strings.Contains(got, "lines=1") {
		t.Errorf("non-JSON output should be counted as unparsed, got %q", got)
	}
	if strings.Contains(got, "/home/someone/private") {
		t.Errorf("non-JSON output leaked its text: %q", got)
	}

	// A truncated buffer must be flagged, not silently trimmed.
	long := strings.Repeat(`{"level":"info","ts":1,"logger":"http","msg":"server running"}`+"\n", 40000)
	if got := caddyStderrDigest(long); !strings.Contains(got, "truncated=true") {
		t.Errorf("oversized input should report truncated=true, got %q", got[:min(len(got), 200)])
	}

	// The event cap must be reported rather than exceeded.
	var many strings.Builder
	for i := 0; i < caddyDigestEventLimit+5; i++ {
		fmt.Fprintf(&many, `{"level":"info","ts":%d,"logger":"http","msg":"server running"}`+"\n", 100+i)
	}
	capped := caddyStderrDigest(many.String())
	if !strings.Contains(capped, "suppressed=5") {
		t.Errorf("event cap should report suppressed=5, got %q", capped)
	}
	if n := strings.Count(capped, "\n    +"); n != caddyDigestEventLimit {
		t.Errorf("timeline should hold %d events, got %d", caddyDigestEventLimit, n)
	}
}

// TestCaddyDiagnosticsFailingSubprocessReportsSafeEvidence runs the controlled
// failing fixture in a real child process and checks the two properties that
// matter: the failure stays nonzero, and its output carries the safe diagnostic
// with none of the hostile material.
func TestCaddyDiagnosticsFailingSubprocessReportsSafeEvidence(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCaddyDiagnosticsHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "CADDY_DIAGNOSTICS_HELPER=1")

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("controlled failing fixture exited zero; a failing Caddy fixture must stay nonzero")
	}

	text := string(out)
	if !strings.Contains(text, "CADDY_DIAGNOSTICS[controlled-fixture]") {
		t.Fatalf("failing output is missing the safe diagnostic header:\n%s", text)
	}
	if !strings.Contains(text, "acquisition.error class=permission-denied") {
		t.Errorf("failing output is missing the acquisition classification:\n%s", text)
	}
	for _, marker := range hostileCaddyMarkers {
		if strings.Contains(text, marker) {
			t.Errorf("failing output leaked %q", marker)
		}
	}
}
