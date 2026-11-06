//go:build linux

package vpn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// This file adds the minimum prerequisite/namespace/error readback that the
// issue-678 activation failure could not answer (ACTIVATION_FAILURE_DIAGNOSIS.md
// §7): it observes the preparation context and the activation-child context that
// the existing Linux-E2E fixture already creates.
//
// It performs no configuration of its own: no host sysctl, no mount, no
// remount, no new write, no capability or container change. It only reads the
// same procfs keys the production guard reads, plus namespace identity and the
// /proc mount class, and it compares them across contexts. It deliberately does
// NOT conclude *why* two contexts differ: a failed or unchanged value is
// reported as an observation class, never as an established kernel mechanism.
//
// Output is synthetic: numeric readbacks, relative namespace identity tokens and
// error categories. No host path, address, raw command output or credential is
// logged. The raw namespace identity is exchanged between the re-executed probe
// and this process so identity can be compared, and is never logged.

const (
	// envPolicyE2EContextProbe turns the re-executed binary into a one-shot
	// context readback: it prints a single PROBECONTEXT line and exits. It runs
	// inside the namespace via the same `ip netns exec <ns>` wrapper the fixture
	// already uses for preparation, so the readback happens in that exact context
	// family rather than being inferred.
	envPolicyE2EContextProbe = "NEXUS_POLICY_E2E_CONTEXT_PROBE"
	// envPolicyE2ENetnsRef carries the namespace identity the readback compares
	// itself against, so the report is a same/different token instead of an inode.
	envPolicyE2ENetnsRef = "NEXUS_POLICY_E2E_NETNS_REF"
	// envPolicyE2EPrepReadback carries the preparation-context readback line to
	// the activation child, so the child can classify its own context against the
	// one the fixture prepared in.
	envPolicyE2EPrepReadback = "NEXUS_POLICY_E2E_PREP_READBACK"

	// policyE2EWANDevice is the device name production creates and configures
	// per-device accept_local on (internal/vpn/vpn_pbr.go NewProductionWANDevice).
	policyE2EWANDevice = "nexus-wan0"

	probeContextPrefix = "PROBECONTEXT "
)

// policyE2EContextReadback is one context's synthetic observation. Values are
// kept as short tokens rather than parsed booleans so an unreadable key stays
// distinguishable from a readable zero.
type policyE2EContextReadback struct {
	NetnsID       string // raw namespace identity; exchanged, never logged
	NetnsRelation string // "same" | "different" | "unknown" vs the reference
	IPForward     string // numeric readback | "unreadable" | "other"
	RPFilter      string
	AcceptLocal   string
	ProcMount     string // "rw" | "ro" | "absent" | "unknown"
	ProcSysMount  string // separate /proc/sys mount, when the kernel exposes one
	DeviceLocal   string // per-device accept_local: value | "absent" | "unreadable"
}

// readPolicyE2EContext observes the calling process's view of the prerequisites.
// The reader is the process itself, so the values are exactly what a production
// guard in this process would read.
func readPolicyE2EContext(reference string) policyE2EContextReadback {
	id := readPolicyE2ENetnsID()
	return policyE2EContextReadback{
		NetnsID:       id,
		NetnsRelation: policyE2ENetnsRelation(id, reference),
		IPForward:     readPolicyE2ENumericValue("/proc/sys/net/ipv4/ip_forward"),
		RPFilter:      readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/rp_filter"),
		AcceptLocal:   readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/accept_local"),
		ProcMount:     readPolicyE2EMountClass("/proc"),
		ProcSysMount:  readPolicyE2EMountClass("/proc/sys"),
	}
}

func readPolicyE2ENetnsID() string {
	target, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ""
	}
	return target
}

func policyE2ENetnsRelation(id, reference string) string {
	if id == "" || reference == "" {
		return "unknown"
	}
	if id == reference {
		return "same"
	}
	return "different"
}

// readPolicyE2ENumericValue reads one numeric procfs key and reduces it to digits,
// so an unexpected kernel response cannot leak arbitrary file content into a log.
func readPolicyE2ENumericValue(path string) string {
	// #nosec G304 -- fixed procfs keys defined in this file
	data, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	return sanitizePolicyE2ENumeric(data)
}

func sanitizePolicyE2ENumeric(data []byte) string {
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "other"
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return "other"
		}
	}
	return value
}

// readPolicyE2EDeviceValue distinguishes a missing interface from an unreadable
// key from a readable value, which is what the guard failure could not say.
func readPolicyE2EDeviceValue(path string) string {
	// #nosec G304 -- fixed procfs key constructed from a constant device name
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "absent"
		}
		return "unreadable"
	}
	return sanitizePolicyE2ENumeric(data)
}

// readPolicyE2EMountClass reports whether the mountpoint is read-only, read-write
// or not present. It distinguishes the mount flag from the sysctl value: a
// readable-writable mount and an unchanged value are separate observations.
func readPolicyE2EMountClass(mountpoint string) string {
	// #nosec G304 -- fixed procfs mount table
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != mountpoint {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if opt == "ro" {
				return "ro"
			}
		}
		return "rw"
	}
	return "absent"
}

// report renders the loggable form: no raw namespace identity, no host path.
func (rb policyE2EContextReadback) report() string {
	return fmt.Sprintf("netns=%s ip_forward=%s rp_filter=%s accept_local=%s proc=%s proc_sys=%s device_accept_local=%s",
		rb.NetnsRelation, rb.IPForward, rb.RPFilter, rb.AcceptLocal,
		rb.ProcMount, emptyPolicyE2EToken(rb.ProcSysMount), emptyPolicyE2EToken(rb.DeviceLocal))
}

func emptyPolicyE2EToken(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

// firstPolicyE2EToken returns the first token of utility output, and only if it
// looks like an inert identifier, so a utility message cannot carry a host path or
// address into a CI log. Anything else collapses to "detail-omitted".
func firstPolicyE2EToken(output string) string {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return "no-detail"
	}
	first := fields[0]
	if len(first) > 32 {
		return "detail-omitted"
	}
	for _, r := range first {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == ':':
		default:
			return "detail-omitted"
		}
	}
	return first
}

// policyE2EObservedToken renders a classifier verdict without overstating it.
func policyE2EObservedToken(ok bool) string {
	if ok {
		return "observed"
	}
	return "not-observed"
}

// line renders the exchange form used between the probe re-exec and this process.
func (rb policyE2EContextReadback) line() string {
	return probeContextPrefix + "id=" + rb.NetnsID + " " + rb.report()
}

// parsePolicyE2EContextLine recovers a readback from a probe's output. It returns
// ok=false when the probe never produced a line, so an unavailable observation is
// never mistaken for a negative one.
func parsePolicyE2EContextLine(out string) (policyE2EContextReadback, bool) {
	var rb policyE2EContextReadback
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, probeContextPrefix) {
			continue
		}
		found = true
		for _, field := range strings.Fields(strings.TrimPrefix(line, probeContextPrefix)) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch key {
			case "id":
				rb.NetnsID = value
			case "netns":
				rb.NetnsRelation = value
			case "ip_forward":
				rb.IPForward = value
			case "rp_filter":
				rb.RPFilter = value
			case "accept_local":
				rb.AcceptLocal = value
			case "proc":
				rb.ProcMount = value
			case "proc_sys":
				rb.ProcSysMount = value
			case "device_accept_local":
				rb.DeviceLocal = value
			}
		}
	}
	return rb, found
}

// Observation classes. Each names what was seen, not why.
const (
	policyE2EReadbackPrerequisitesVisible     = "prerequisites-visible-in-activation-context"
	policyE2EReadbackPrepOutsideTestNamespace = "preparation-context-not-in-test-namespace"
	policyE2EReadbackActivationOutsidePrepNS  = "activation-context-not-in-prepared-namespace"
	policyE2EReadbackPreparedNotVisible       = "prepared-values-not-visible-in-activation-context"
	policyE2EReadbackPreparationIneffective   = "preparation-operation-did-not-take-effect"
	policyE2EReadbackInconclusive             = "readback-inconclusive"
)

// classifyPrerequisiteReadback compares the preparation context with the
// activation context. ok=true means every prerequisite the production guard
// requires was observed as satisfied in the activation context.
//
// Neither an equal namespace nor a differing value establishes a kernel
// mechanism: an unchanged value only says the preparation operation did not take
// effect where it was observed, and a namespace difference only says the two
// observations were made in different network namespaces.
func classifyPrerequisiteReadback(prep, activation policyE2EContextReadback) (string, bool) {
	for _, rb := range []policyE2EContextReadback{prep, activation} {
		if rb.NetnsRelation == "" || rb.NetnsRelation == "unknown" ||
			rb.IPForward == "unreadable" || rb.RPFilter == "unreadable" || rb.AcceptLocal == "unreadable" ||
			rb.IPForward == "other" || rb.RPFilter == "other" || rb.AcceptLocal == "other" {
			return policyE2EReadbackInconclusive, false
		}
	}
	// The preparation wrapper should enter a different namespace than the one the
	// caller is in; "same" means the wrapper did not isolate the observation.
	if prep.NetnsRelation == "same" {
		return policyE2EReadbackPrepOutsideTestNamespace, false
	}
	if activation.NetnsRelation != "same" {
		return policyE2EReadbackActivationOutsidePrepNS, false
	}
	prepared := prerequisitesObserved(prep)
	if prerequisitesObserved(activation) {
		return policyE2EReadbackPrerequisitesVisible, true
	}
	if prepared {
		return policyE2EReadbackPreparedNotVisible, false
	}
	return policyE2EReadbackPreparationIneffective, false
}

// classifyPreparationReadback judges a single preparation-context observation on
// its own, without an activation-side counterpart. It answers one question only:
// are the prerequisites the production guard requires visible in the wrapper the
// fixture prepares in?
func classifyPreparationReadback(prep policyE2EContextReadback) (string, bool) {
	switch {
	case prep.NetnsRelation == "" || prep.NetnsRelation == "unknown":
		return policyE2EReadbackInconclusive, false
	case prep.IPForward == "unreadable" || prep.RPFilter == "unreadable" || prep.AcceptLocal == "unreadable":
		return policyE2EReadbackInconclusive, false
	case prep.IPForward == "other" || prep.RPFilter == "other" || prep.AcceptLocal == "other":
		return policyE2EReadbackInconclusive, false
	case prep.NetnsRelation == "same":
		return policyE2EReadbackPrepOutsideTestNamespace, false
	case prerequisitesObserved(prep):
		return policyE2EReadbackPrerequisitesVisible, true
	default:
		return policyE2EReadbackPreparationIneffective, false
	}
}

// prerequisitesObserved reports whether one readback shows the three keys the
// production guard checks: ip_forward=1, rp_filter not strict, accept_local=1.
func prerequisitesObserved(rb policyE2EContextReadback) bool {
	return rb.IPForward == "1" && rb.RPFilter != "1" && rb.AcceptLocal == "1"
}

// runPolicyE2EContextProbe is the re-exec entry point: read, print, exit.
func runPolicyE2EContextProbe() int {
	rb := readPolicyE2EContext(os.Getenv(envPolicyE2ENetnsRef))
	fmt.Println(rb.line())
	return 0
}

// policyE2EActivationBoundary observes the child's own context at the activation
// boundary and classifies it against the preparation readback the parent passed.
//
// It is observation only: it returns a report and a class, and never changes the
// activation path or the guard's decision. A class of "inconclusive" is reported as
// such rather than as a negative result.
func policyE2EActivationBoundary() (policyE2EContextReadback, string, bool) {
	prep, _ := parsePolicyE2EContextLine(os.Getenv(envPolicyE2EPrepReadback))
	activation := readPolicyE2EContext(prep.NetnsID)
	class, ok := classifyPrerequisiteReadback(prep, activation)
	return activation, class, ok
}

// observePreparationContext reads the prerequisites from the same `ip netns exec`
// wrapper family the fixture prepares in. One extra process start, no new write.
func observePreparationContext(t *testing.T, ns string) (policyE2EContextReadback, bool) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		envPolicyE2EContextProbe+"=1",
		envPolicyE2ENetnsRef+"="+readPolicyE2ENetnsID(),
	)
	out, runErr := cmd.CombinedOutput()
	rb, parsed := parsePolicyE2EContextLine(string(out))
	if !parsed {
		t.Logf("preparation-context readback unavailable: probe-did-not-report=%t probe-failed=%t", !parsed, runErr != nil)
		return rb, false
	}
	// Only the synthetic report is logged; the raw command output is not.
	t.Logf("preparation-context readback: %s", rb.report())
	return rb, runErr == nil
}

// describePolicyE2EDeviceReadback reports the per-device key production configures,
// so a guard failure distinguishes a missing interface from an unapplied value.
func describePolicyE2EDeviceReadback() string {
	path := "/proc/sys/net/ipv4/conf/" + policyE2EWANDevice + "/accept_local"
	return "device_accept_local=" + readPolicyE2EDeviceValue(path)
}

// classifyPolicyE2EPrepareFailure names the class of an existing preparation
// command failure, so a missing utility is distinguishable from a refused one
// without recording arbitrary command output.
func classifyPolicyE2EPrepareFailure(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return "utility-missing"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() > 0 {
			return "utility-exit-status"
		}
		return "utility-signaled"
	}
	return "other"
}

// ---- offline controls -------------------------------------------------------
//
// These prove the classifier and the sanitizers without privileges, a namespace,
// a container or a host write: the same pattern the repository already uses for
// classifyPrerequisiteOutcome.

func TestPolicyE2EPrerequisiteReadbackClassification(t *testing.T) {
	met := func(relation string) policyE2EContextReadback {
		return policyE2EContextReadback{NetnsRelation: relation, IPForward: "1", RPFilter: "2", AcceptLocal: "1"}
	}
	unsatisfied := func(relation string) policyE2EContextReadback {
		return policyE2EContextReadback{NetnsRelation: relation, IPForward: "1", RPFilter: "2", AcceptLocal: "0"}
	}
	with := func(base policyE2EContextReadback, mutate func(*policyE2EContextReadback)) policyE2EContextReadback {
		mutate(&base)
		return base
	}

	tests := []struct {
		name       string
		prep       policyE2EContextReadback
		activation policyE2EContextReadback
		wantClass  string
		wantOK     bool
	}{
		{
			name:       "preparation wrapper did not isolate",
			prep:       met("same"),
			activation: met("same"),
			wantClass:  policyE2EReadbackPrepOutsideTestNamespace,
		},
		{
			name:       "prerequisites visible in both contexts",
			prep:       met("different"),
			activation: met("same"),
			wantClass:  policyE2EReadbackPrerequisitesVisible,
			wantOK:     true,
		},
		{
			name:       "prepared values not visible in activation context",
			prep:       met("different"),
			activation: unsatisfied("same"),
			wantClass:  policyE2EReadbackPreparedNotVisible,
		},
		{
			name:       "preparation never took effect",
			prep:       unsatisfied("different"),
			activation: unsatisfied("same"),
			wantClass:  policyE2EReadbackPreparationIneffective,
		},
		{
			name:       "activation context outside the prepared namespace",
			prep:       met("different"),
			activation: met("different"),
			wantClass:  policyE2EReadbackActivationOutsidePrepNS,
		},
		{
			name:       "unreadable key is inconclusive, not negative",
			prep:       met("different"),
			activation: with(met("same"), func(rb *policyE2EContextReadback) { rb.AcceptLocal = "unreadable" }),
			wantClass:  policyE2EReadbackInconclusive,
		},
		{
			name:       "unknown namespace relation is inconclusive",
			prep:       met("unknown"),
			activation: met("same"),
			wantClass:  policyE2EReadbackInconclusive,
		},
		{
			name:       "non-numeric kernel response is inconclusive",
			prep:       met("different"),
			activation: with(met("same"), func(rb *policyE2EContextReadback) { rb.IPForward = "other" }),
			wantClass:  policyE2EReadbackInconclusive,
		},
		{
			name:       "strict rp_filter is not satisfied",
			prep:       met("different"),
			activation: with(met("same"), func(rb *policyE2EContextReadback) { rb.RPFilter = "1" }),
			wantClass:  policyE2EReadbackPreparedNotVisible,
		},
		{
			name:       "forwarding off in activation context",
			prep:       met("different"),
			activation: with(met("same"), func(rb *policyE2EContextReadback) { rb.IPForward = "0" }),
			wantClass:  policyE2EReadbackPreparedNotVisible,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := classifyPrerequisiteReadback(tc.prep, tc.activation)
			if class != tc.wantClass || ok != tc.wantOK {
				t.Fatalf("classifyPrerequisiteReadback() = (%q, %t), want (%q, %t)", class, ok, tc.wantClass, tc.wantOK)
			}
		})
	}
}

// TestPolicyE2ERealContextReadback exercises the reading path against this
// process's real /proc (no namespace, no privileges, no write) and asserts only
// that every field is a token the classifier understands. It proves the readback
// cannot emit arbitrary file content, not that any prerequisite is satisfied.
func TestPolicyE2ERealContextReadback(t *testing.T) {
	rb := readPolicyE2EContext("")
	allowed := map[string][]string{
		"ip_forward":   {"0", "1", "other", "unreadable"},
		"rp_filter":    {"0", "1", "2", "other", "unreadable"},
		"accept_local": {"0", "1", "other", "unreadable"},
		"proc":         {"ro", "rw", "absent", "unknown"},
		"proc_sys":     {"ro", "rw", "absent", "unknown"},
	}
	got := map[string]string{
		"ip_forward":   rb.IPForward,
		"rp_filter":    rb.RPFilter,
		"accept_local": rb.AcceptLocal,
		"proc":         rb.ProcMount,
		"proc_sys":     rb.ProcSysMount,
	}
	for field, value := range got {
		valid := false
		for _, want := range allowed[field] {
			if value == want {
				valid = true
				break
			}
		}
		if !valid {
			t.Fatalf("%s readback = %q, not one of the allowed tokens %v", field, value, allowed[field])
		}
	}
	// With no reference supplied the relation must be the honest "unknown", not a
	// fabricated "same"/"different".
	if rb.NetnsRelation != "unknown" {
		t.Fatalf("relation without a reference = %q, want \"unknown\"", rb.NetnsRelation)
	}
	if rb.ProcMount == "unknown" {
		t.Logf("note: /proc mount class unavailable in this environment")
	}
}

func TestPolicyE2EPreparationReadbackClassification(t *testing.T) {
	tests := []struct {
		name      string
		prep      policyE2EContextReadback
		wantClass string
		wantOK    bool
	}{
		{
			name:      "prepared values visible in the preparation wrapper",
			prep:      policyE2EContextReadback{NetnsRelation: "different", IPForward: "1", RPFilter: "2", AcceptLocal: "1"},
			wantClass: policyE2EReadbackPrerequisitesVisible,
			wantOK:    true,
		},
		{
			name:      "loose rp_filter value 0 also satisfies the guard",
			prep:      policyE2EContextReadback{NetnsRelation: "different", IPForward: "1", RPFilter: "0", AcceptLocal: "1"},
			wantClass: policyE2EReadbackPrerequisitesVisible,
			wantOK:    true,
		},
		{
			name:      "preparation operation did not take effect",
			prep:      policyE2EContextReadback{NetnsRelation: "different", IPForward: "0", RPFilter: "2", AcceptLocal: "1"},
			wantClass: policyE2EReadbackPreparationIneffective,
		},
		{
			name:      "wrapper did not enter the test namespace",
			prep:      policyE2EContextReadback{NetnsRelation: "same", IPForward: "1", RPFilter: "2", AcceptLocal: "1"},
			wantClass: policyE2EReadbackPrepOutsideTestNamespace,
		},
		{
			name:      "unreadable key stays inconclusive",
			prep:      policyE2EContextReadback{NetnsRelation: "different", IPForward: "1", RPFilter: "2", AcceptLocal: "unreadable"},
			wantClass: policyE2EReadbackInconclusive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := classifyPreparationReadback(tc.prep)
			if class != tc.wantClass || ok != tc.wantOK {
				t.Fatalf("classifyPreparationReadback() = (%q, %t), want (%q, %t)", class, ok, tc.wantClass, tc.wantOK)
			}
		})
	}
}

func TestPolicyE2EContextReadbackRoundTrip(t *testing.T) {
	original := policyE2EContextReadback{
		NetnsID:       "net:[4026532000]",
		NetnsRelation: "different",
		IPForward:     "1",
		RPFilter:      "2",
		AcceptLocal:   "1",
		ProcMount:     "rw",
		ProcSysMount:  "ro",
		DeviceLocal:   "absent",
	}

	parsed, ok := parsePolicyE2EContextLine("noise before\n" + original.line() + "\nnoise after\n")
	if !ok {
		t.Fatal("parsePolicyE2EContextLine did not find the probe line")
	}
	if parsed != original {
		t.Fatalf("round trip mismatch: got %+v want %+v", parsed, original)
	}

	// The identity is exchanged between processes but must never appear in the
	// loggable report.
	if strings.Contains(original.report(), "4026532000") || strings.Contains(original.report(), "/proc/") {
		t.Fatalf("report leaked raw identity or host path: %q", original.report())
	}

	if _, ok := parsePolicyE2EContextLine("no probe line here\n"); ok {
		t.Fatal("parsePolicyE2EContextLine accepted output without a probe line")
	}
}

func TestPolicyE2ENumericReadbackSanitization(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
		return path
	}

	if got := readPolicyE2ENumericValue(write("numeric", "1\n")); got != "1" {
		t.Fatalf("numeric readback = %q, want \"1\"", got)
	}
	if got := readPolicyE2ENumericValue(write("junk", "secret-host=10.0.0.1\n")); got != "other" {
		t.Fatalf("non-numeric readback = %q, want \"other\" (must not echo content)", got)
	}
	if got := readPolicyE2ENumericValue(write("empty", "\n")); got != "other" {
		t.Fatalf("empty readback = %q, want \"other\"", got)
	}
	if got := readPolicyE2ENumericValue(dir + "/missing"); got != "unreadable" {
		t.Fatalf("missing readback = %q, want \"unreadable\"", got)
	}
	if got := readPolicyE2EDeviceValue(dir + "/missing"); got != "absent" {
		t.Fatalf("missing device readback = %q, want \"absent\"", got)
	}
	if got := readPolicyE2EMountClass("/nonexistent-mountpoint-for-test"); got != "absent" {
		t.Fatalf("absent mountpoint class = %q, want \"absent\"", got)
	}
	if got := readPolicyE2EMountClass("/proc"); got != "rw" && got != "ro" {
		t.Fatalf("real /proc mount class = %q, want \"rw\" or \"ro\"", got)
	}
}

func TestPolicyE2EPrepareFailureClassification(t *testing.T) {
	if got := classifyPolicyE2EPrepareFailure(nil); got != "none" {
		t.Fatalf("nil error class = %q, want \"none\"", got)
	}
	if got := classifyPolicyE2EPrepareFailure(exec.ErrNotFound); got != "utility-missing" {
		t.Fatalf("missing utility class = %q, want \"utility-missing\"", got)
	}
	exitErr := exec.Command("sh", "-c", "exit 3").Run()
	if got := classifyPolicyE2EPrepareFailure(exitErr); got != "utility-exit-status" {
		t.Fatalf("exit status class = %q, want \"utility-exit-status\"", got)
	}
	if got := classifyPolicyE2EPrepareFailure(errors.New("boom")); got != "other" {
		t.Fatalf("unclassified error = %q, want \"other\"", got)
	}
}
