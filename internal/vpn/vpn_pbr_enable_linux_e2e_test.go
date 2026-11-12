//go:build linux

package vpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file provides the positive acceptance path for issue #678: a real
// admin/settings/source -> production activation -> restart -> disable cycle,
// executed against the authentic Linux data path rather than a stubbed one.
//
// It is deliberately part of the existing Linux-E2E family and reuses the
// established re-exec-into-a-network-namespace pattern from
// internal/vpn/forwarder/direct_egress_linux_e2e_test.go, so there is no new
// framework, runner, image or workflow.
//
// Why a namespace: ValidateKernelPrerequisites reads per-netns procfs keys
// (net.ipv4.ip_forward, conf/all/rp_filter, conf/all/accept_local). Creating a
// private namespace and configuring *that* namespace lets the real prerequisite
// checks pass legitimately, instead of loosening them or injecting fake success.
// No host sysctl is touched.
//
// Why the child also isolates a mount namespace: the CI job container mounts
// `/proc` read-write but `/proc/sys` as a separate read-only mount (measured as
// `proc=rw proc_sys=ro` in evidence/namespace-readback-ci/test-job.log). A
// `sysctl -w` in that container therefore cannot take effect while still exiting
// 0, which is why a previous revision prepared nothing and the activation child
// read `accept_local=0`. The child now mounts its own private procfs inside a
// mount namespace that is verified private first, so the prerequisites are
// written and read back by the same process whose view the guard consumes. That
// uses only the capabilities the job already grants (SYS_ADMIN for the mount
// namespace, NET_ADMIN/NET_RAW and /dev/net/tun as before).
//
// CI registration is deliberate: .github/workflows/ci.yml's existing Linux-E2E
// step targets ./internal/vpn/forwarder/..., which does NOT include this package.
// A second explicit step selects ./internal/vpn/ so this test actually runs; a
// test that is never executed would be a green pipeline proving nothing.

const (
	// envPolicyE2EChild marks the re-executed child that performs the privileged
	// work inside the namespace. The parent asserts on its exit status and output.
	envPolicyE2EChild = "NEXUS_POLICY_E2E_CHILD"
	// envPolicyE2ENetns carries the namespace name to the child.
	envPolicyE2ENetns = "NEXUS_POLICY_E2E_NETNS"

	policyE2ENetns  = "nexus-pbr-policy"
	policyE2EVeth   = "pbr-veth0"
	policyE2EPeer   = "pbr-peer0"
	policyE2ETun    = "pbr-wan0"
	policyE2ESubnet = "198.51.200"
)

func init() {
	// Re-exec entry point, mirroring the existing Linux-E2E echo helper. The child
	// runs the real activation and exits non-zero on any failure.
	if os.Getenv(envPolicyE2EChild) == "1" {
		os.Exit(runPolicyEnablementChild())
	}
}

// policyE2EGate reports whether this environment can run the privileged flow.
// In CI every unmet prerequisite is a failure: silently skipping here would turn a
// broken capability contract into a passing build. Locally it skips, because an
// unprivileged development host legitimately cannot provide these.
func policyE2EGate(t *testing.T) bool {
	t.Helper()
	inCI := os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
	unmet := func(format string, args ...any) bool {
		if inCI {
			t.Fatalf("policy enablement E2E prerequisite unmet: "+format, args...)
		} else {
			t.Skipf("skipping policy enablement E2E: "+format, args...)
		}
		return false
	}

	if os.Geteuid() != 0 {
		return unmet("root privileges required (namespace and device creation)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return unmet("ip command not found")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return unmet("iptables not found")
	}
	if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err != nil {
		return unmet("cannot open /dev/net/tun: %v", err)
	} else {
		_ = f.Close()
	}
	// The production WAN device opens an AF_PACKET capture socket, which requires
	// CAP_NET_RAW specifically; CAP_NET_ADMIN alone is insufficient. Probe exactly
	// what production probes so a missing capability names itself here.
	if err := checkWANCaptureCapability(); err != nil {
		return unmet("AF_PACKET WAN capture unavailable (needs --cap-add NET_RAW): %v", err)
	}
	return true
}

// TestLinuxE2E_PolicyEnablement proves the full 678 positive path:
// persisted admin settings + real policy source -> production PBR activation ->
// restart reproducing the configuration -> disable returning to all-proxy.
func TestLinuxE2E_PolicyEnablement(t *testing.T) {
	if !policyE2EGate(t) {
		return
	}

	ns := fmt.Sprintf("%s-%d", policyE2ENetns, time.Now().UnixNano()%100000)
	if err := exec.Command("ip", "netns", "add", ns).Run(); err != nil {
		t.Fatalf("ip netns add failed: %v", err)
	}
	defer func() { _ = exec.Command("ip", "netns", "del", ns).Run() }()

	// Re-exec this binary inside the namespace so procfs reads resolve to the
	// namespace's own values. The child also isolates its mount namespace and
	// prepares the prerequisites there, because it is the process whose view the
	// production guard reads; see the file comment.
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=TestLinuxE2E_PolicyEnablementChild", "-test.v")
	cmd.Env = append(os.Environ(), envPolicyE2EChild+"=1", envPolicyE2ENetns+"="+ns)
	out, err := cmd.CombinedOutput()
	t.Logf("child output:\n%s", out)
	if err != nil {
		t.Fatalf("policy enablement child failed: %v", err)
	}

	// The child reports structured phases; assert each positive transition was
	// actually observed rather than trusting only an exit code.
	required := []string{
		"PHASE settings-persisted",
		"PHASE activation-enabled",
		"PHASE restart-restored",
		"PHASE disable-all-proxy",
		"PHASE negatives-hold",
	}
	for _, marker := range required {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("child did not report %q; the corresponding positive step never ran", marker)
		}
	}
}

// TestLinuxE2E_PolicyEnablementChild is the in-namespace worker. It is only ever
// reached through the re-exec above; a direct run is a no-op so it cannot be
// mistaken for a real qualification.
func TestLinuxE2E_PolicyEnablementChild(t *testing.T) {
	if os.Getenv(envPolicyE2EChild) != "1" {
		t.Skip("child harness: executed only via the namespace re-exec from TestLinuxE2E_PolicyEnablement")
	}
	// The real work happens in runPolicyEnablementChild (init), which has already
	// exited by now if the re-exec worked.
}

// runPolicyEnablementChild isolates the test's own mount namespace, prepares the
// production guard's prerequisites inside it, then performs the full positive
// cycle. It returns a process exit code.
//
// The isolation and its cleanup live in this function rather than in the re-exec
// entry point so the deferred detach runs on both the success and the failure
// path; os.Exit is only reached after this function has returned.
func runPolicyEnablementChild() int {
	// A mount namespace is per-thread, so the fresh procfs is only visible to the
	// thread that mounted it. Pin this goroutine for the whole privileged section
	// so the synchronous production prerequisite reads stay on that thread instead
	// of resolving against another thread's mount view.
	//
	// Deliberately not unlocked: this process exits immediately after the child
	// returns, and Go terminates a thread that exits while locked rather than
	// returning it to the runtime pool. Unlocking would hand a thread whose mount
	// namespace this test rewrote back to the scheduler in a live process.
	runtime.LockOSThread()

	cleanup, err := enterPolicyE2EPrivateProcfs(realPolicyE2EMountOps())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: isolate test mount namespace: %v\n", err)
		return 1
	}
	defer cleanup()

	return runPolicyEnablementChildInPrivateProcfs()
}

// runPolicyEnablementChildInPrivateProcfs performs the positive cycle inside the
// namespace and private procfs established by runPolicyEnablementChild.
func runPolicyEnablementChildInPrivateProcfs() int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
		return 1
	}
	say := func(line string) { fmt.Println(line) }

	// ---- Prepare and verify the production guard's prerequisites -------------
	// Written and read back in this process, which is the one that runs the real
	// activation and therefore the one whose procfs view the guard reads. A step
	// that does not take effect fails here, naming the class, instead of surfacing
	// later as a product prerequisite failure.
	if err := applyPolicyE2EPrerequisites(policyE2ESysctlRoot); err != nil {
		fmt.Fprintf(os.Stderr, "READBACK preparation-context %s\n", reportPolicyE2EContext())
		return fail("test environment cannot provide its own prerequisites: %v; "+
			"the production guard was never loosened and activation was not attempted", err)
	}
	say("READBACK preparation-context " + reportPolicyE2EContext())

	// ---- Bring up the namespace's own network plumbing ------------------------
	steps := [][]string{
		{"ip", "tuntap", "add", "dev", policyE2ETun, "mode", "tun"},
		{"ip", "link", "set", policyE2ETun, "up"},
		{"ip", "link", "add", policyE2EVeth, "type", "veth", "peer", "name", policyE2EPeer},
		{"ip", "addr", "add", policyE2ESubnet + ".1/24", "dev", policyE2EVeth},
		{"ip", "link", "set", policyE2EVeth, "up"},
		{"ip", "link", "set", policyE2EPeer, "up"},
		{"ip", "link", "set", "lo", "up"},
		{"ip", "route", "add", "default", "via", policyE2ESubnet + ".2"},
	}
	for _, step := range steps {
		if out, err := exec.Command(step[0], step[1:]...).CombinedOutput(); err != nil {
			return fail("network setup %q: %s (%s)", strings.Join(step, " "),
				classifyPolicyE2EPrepareFailure(err), strings.TrimSpace(string(out)))
		}
	}

	// ---- Authentic fixture-scoped HTTPS policy source -------------------------
	listBody := "example.com\ncdn.example.net\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(listBody))
	}))
	defer srv.Close()

	// ---- 1. admin/settings/source: persist the record -------------------------
	dataDir, err := os.MkdirTemp("", "nexus-pbr-e2e-")
	if err != nil {
		return fail("temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dataDir) }()

	db, err := openPolicyE2EDB(dataDir)
	if err != nil {
		return fail("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	settings := policyE2ESettingsForFixture(srv.URL)
	if err := settings.Validate(); err != nil {
		return fail("fixture settings invalid: %v", err)
	}
	if err := persistPolicyE2ESettings(db, settings); err != nil {
		return fail("persist settings: %v", err)
	}
	// Read back through the same store the admin GET uses: this is the persistence
	// half of acceptance, not an in-memory shortcut.
	reloaded, err := loadPolicyE2ESettings(db)
	if err != nil {
		return fail("reload settings: %v", err)
	}
	if reloaded.Preset != settings.Preset || reloaded.Enabled != settings.Enabled {
		return fail("persisted settings did not round-trip: got %+v want %+v", reloaded, settings)
	}
	say("PHASE settings-persisted")

	// ---- 2. production activation --------------------------------------------
	store := policyE2EFileStore(dataDir)
	// Pre-seed the durable last-known-good generation with the fixture list the way
	// a successful earlier sync would. This makes activation deterministic inside the
	// namespace (no dependency on the fixture server being reachable from it) while
	// still exercising the real sync -> commit -> publish path.
	if _, syncRes, err := runPolicyE2ESync(settings, store, srv); err != nil {
		return fail("priming policy sync: %v", err)
	} else if !syncRes.Published {
		return fail("priming policy sync did not publish a snapshot")
	}

	svc, err := newPolicyE2EService()
	if err != nil {
		return fail("new service: %v", err)
	}
	if err := activatePolicyE2E(svc, settings, store); err != nil {
		// Name the environment facts the guard's own error cannot: the per-device
		// key it tried to configure, and this context's re-read after the refusal.
		// The guard still decides; this only makes a refusal actionable.
		fmt.Fprintf(os.Stderr, "READBACK activation-failure %s\n", reportPolicyE2EContext())
		return fail("activation: %v", err)
	}
	if !svc.PBREnabled() {
		return fail("PBREnabled() = false immediately after activation")
	}
	if svc.DirectEgress() == nil {
		return fail("DirectEgress() = nil after activation")
	}
	if snap := svc.PolicyMatcher().Current(); snap == nil || snap.DomainCount() == 0 {
		return fail("no rule-bearing snapshot published by activation")
	}
	say("PHASE activation-enabled")

	// ---- 3. restart: new service + new startup, same durable store -----------
	// Release the first data path before the replacement starts. A real panel
	// restart is a process restart, where the old TUN descriptor dies with the
	// process and the device name becomes free; here both Services live in one
	// process, so the first must hand the name over explicitly or the second
	// creation fails with EBUSY. This models the restart boundary at the
	// resource-lifetime level instead of asserting an ownership the fixture does
	// not have.
	svc.StopPolicyRouting()
	// Assert the hand-over really happened, so a regression names the boundary
	// instead of surfacing as a device conflict during the replacement.
	if svc.PBREnabled() || svc.DirectEgress() != nil || svc.PolicyMatcher() != nil {
		return fail("the first service still owns its data path after restart hand-over "+
			"(pbr_enabled=%t direct_egress_set=%t matcher_set=%t)",
			svc.PBREnabled(), svc.DirectEgress() != nil, svc.PolicyMatcher() != nil)
	}
	svc2, err := newPolicyE2EService()
	if err != nil {
		return fail("new service (restart): %v", err)
	}
	reloaded2, err := loadPolicyE2ESettings(db)
	if err != nil {
		return fail("reload settings after restart: %v", err)
	}
	if reloaded2.Preset != settings.Preset || reloaded2.SyncInterval != settings.SyncInterval {
		return fail("settings did not survive restart: got %+v want %+v", reloaded2, settings)
	}
	// Activating from persisted settings alone must reproduce the policy from the
	// durable store, proving restart does not depend on in-memory carry-over.
	if err := activatePolicyE2E(svc2, reloaded2, store); err != nil {
		return fail("activation after restart: %v", err)
	}
	if !svc2.PBREnabled() {
		return fail("PBREnabled() = false after restart activation")
	}
	say("PHASE restart-restored")

	// ---- 4. disable: back to the existing all-proxy behavior ----------------
	svc2.StopPolicyRouting()
	if svc2.PBREnabled() {
		return fail("PBREnabled() = true after disable")
	}
	if svc2.DirectEgress() != nil {
		return fail("DirectEgress() still set after disable")
	}
	if svc2.PolicyMatcher() != nil {
		return fail("policy runtime still registered after disable")
	}
	say("PHASE disable-all-proxy")

	// ---- 5. negative controls must still hold -------------------------------
	// Missing source: activation must refuse and must not leave PBR enabled.
	bad := policyE2ESettingsForFixture(srv.URL)
	bad.Preset = "not_a_preset"
	if err := bad.Validate(); err == nil {
		return fail("invalid preset passed Validate; fail-closed validation regressed")
	}
	svc3, err := newPolicyE2EService()
	if err != nil {
		return fail("new service (negative): %v", err)
	}
	if err := activatePolicyE2E(svc3, bad, policyE2EFileStore(dataDir)); err == nil {
		return fail("activation accepted an invalid configuration")
	}
	if svc3.PBREnabled() {
		return fail("PBR enabled after a refused activation")
	}
	say("PHASE negatives-hold")

	fmt.Println("POLICY-E2E-OK")
	return 0
}

// ---- unprivileged portion of the positive chain ----------------------------
//
// This half runs anywhere, including this development host, and covers the parts of
// the 678 acceptance that need no kernel capability: the persisted admin record
// round-tripping through the real settings table, a real fetch/parse/commit/publish
// against a fixture HTTPS list, restart reproducibility, and the negative controls.
//
// It deliberately does NOT claim production activation. Activation requires a real
// TUN device plus an AF_PACKET capture socket, which needs privileges; asserting it
// against a stand-in device would be exactly the "injected successful prerequisite"
// substitute the assignment forbids, and would weaken the positive gate. That step
// lives in TestLinuxE2E_PolicyEnablement and runs only where those capabilities
// genuinely exist.

// TestPolicyEnablementPersistRestartDisableNoPrivileges proves settings persistence,
// source sync, restart reproducibility and disable bookkeeping without privileges.
func TestPolicyEnablementPersistRestartDisableNoPrivileges(t *testing.T) {
	dataDir := t.TempDir()

	listBody := "example.com\ncdn.example.net\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(listBody))
	}))
	defer srv.Close()

	db, err := openPolicyE2EDB(dataDir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	// 1. admin/settings/source persisted through the production settings table.
	settings := policyE2ESettingsForFixture(srv.URL)
	if err := settings.Validate(); err != nil {
		t.Fatalf("fixture settings invalid: %v", err)
	}
	if err := persistPolicyE2ESettings(db, settings); err != nil {
		t.Fatalf("persist settings: %v", err)
	}
	reloaded, err := loadPolicyE2ESettings(db)
	if err != nil {
		t.Fatalf("reload settings: %v", err)
	}
	if reloaded.Preset != settings.Preset || !reloaded.Enabled {
		t.Fatalf("settings did not round-trip through the settings table: got %+v want %+v", reloaded, settings)
	}
	if reloaded.SyncInterval != settings.SyncInterval {
		t.Fatalf("sync interval did not round-trip: got %d want %d", reloaded.SyncInterval, settings.SyncInterval)
	}

	// 2. real source sync: hardened fetch -> parse -> durable commit -> publish.
	store := policyE2EFileStore(dataDir)
	matcher, res, err := runPolicyE2ESync(settings, store, srv)
	if err != nil {
		t.Fatalf("policy sync: %v", err)
	}
	if !res.Published {
		t.Fatal("sync did not publish a snapshot")
	}
	snap := matcher.Current()
	if snap == nil || snap.DomainCount() == 0 {
		t.Fatalf("published snapshot has no domain rules: %+v", snap)
	}
	if !snap.MatchDomain("example.com") {
		t.Error("published snapshot does not match a rule from the fetched list")
	}

	// 3. restart: a fresh DB handle and a fresh store load reproduce the same policy
	// from durable state, proving nothing depends on in-memory carry-over.
	db2, err := openPolicyE2EDB(dataDir)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = db2.Close() }()
	restarted, err := loadPolicyE2ESettings(db2)
	if err != nil {
		t.Fatalf("reload settings after restart: %v", err)
	}
	if restarted.Preset != settings.Preset || restarted.SyncInterval != settings.SyncInterval {
		t.Fatalf("settings did not survive restart: got %+v want %+v", restarted, settings)
	}
	matcher2, res2, err := runPolicyE2ESync(restarted, store, srv)
	if err != nil {
		t.Fatalf("policy sync after restart: %v", err)
	}
	if !res2.Published || matcher2.Current() == nil {
		t.Fatal("no snapshot published after restart")
	}
	// The durable last-known-good generation must also be readable, which is what
	// makes a restart survive a transient network failure later.
	if gen, gerr := store.Load(context.Background()); gerr != nil || gen == nil {
		t.Fatalf("durable last-known-good unreadable after restart: gen=%v err=%v", gen, gerr)
	}

	// 4. disable bookkeeping on a service that never activated: Stop must be safe and
	// leave all-proxy state, so an operator disabling PBR cannot be left half-on.
	svc, err := newPolicyE2EService()
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	svc.StopPolicyRouting()
	if svc.PBREnabled() {
		t.Error("PBREnabled() = true after StopPolicyRouting")
	}
	if svc.PolicyMatcher() != nil {
		t.Error("policy runtime still registered after StopPolicyRouting")
	}

	// 5. negative controls: an invalid record must be refused by validation and must
	// not disturb the stored configuration.
	before, err := loadPolicyE2ESettings(db)
	if err != nil {
		t.Fatalf("reload before negative: %v", err)
	}
	bad := policyE2ESettingsForFixture(srv.URL)
	bad.Preset = "not_a_preset"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid preset passed Validate; fail-closed validation regressed")
	}
	badReq := policyE2ESettingsForFixture(srv.URL)
	badReq.Preset = policy.PresetCustom
	badReq.CustomURLs = []string{"https://10.0.0.5/internal.lst"}
	if err := badReq.Validate(); err == nil {
		t.Fatal("SSRF target passed Validate")
	}
	after, err := loadPolicyE2ESettings(db)
	if err != nil {
		t.Fatalf("reload after negative: %v", err)
	}
	if after.Preset != before.Preset || after.Enabled != before.Enabled {
		t.Fatalf("a rejected configuration modified the stored record: %+v -> %+v", before, after)
	}
}

// openPolicyE2EDB opens the real SQLite store the panel uses, so persistence and
// restart are proven against the production schema rather than a fake.
func openPolicyE2EDB(dataDir string) (*database.DB, error) {
	return database.Open(filepath.Join(dataDir, "panel.db"),
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
}

// policyE2ESettingsForFixture builds a custom-preset record pointed at the fixture
// list. The record must satisfy the real validator, which only permits HTTPS on
// port 443, so the URL uses a canonical form and the fetcher's fixture seam routes
// the connection to the local listener. Only that seam relaxes TLS trust; production
// defaults are untouched.
func policyE2ESettingsForFixture(listURL string) policy.Settings {
	s := policy.DefaultSettings()
	s.Enabled = true
	s.Preset = policy.PresetCustom
	s.CustomURLs = []string{fixtureCanonicalListURL}
	s.SyncInterval = int64(policy.MinSyncInterval.Seconds())
	return s
}

// fixtureCanonicalListURL is the port-443 URL the settings record stores. It passes
// ValidateFetchURL exactly as an operator URL would.
const fixtureCanonicalListURL = "https://lists.example/policy.lst"

func persistPolicyE2ESettings(db *database.DB, settings policy.Settings) error {
	return db.SetSetting(context.Background(), policy.SettingsKey, settings)
}

// loadPolicyE2ESettings reads the record through the same path the admin GET uses.
func loadPolicyE2ESettings(db *database.DB) (policy.Settings, error) {
	settings := policy.DefaultSettings()
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		return settings, err
	}
	if stored.Preset == "" && !stored.Enabled && stored.SyncInterval == 0 && len(stored.CustomURLs) == 0 {
		return settings, nil
	}
	return stored.Normalize(), nil
}

func policyE2EFileStore(dataDir string) policy.Store {
	return policy.NewFileStore(filepath.Join(dataDir, "policy"))
}

// newFixtureFetcher builds the hardened Fetcher but routes its DNS and TCP dial to
// the fixture listener. This is the established fixture seam used by the policy
// package's own fetch tests; production code paths and TLS verification defaults
// are untouched.
func newFixtureFetcher(srv *httptest.Server) *policy.Fetcher {
	serverAddr := srv.Listener.Addr().String()
	f := policy.NewFetcher(policy.FetchLimits{
		MaxSourceBytes: 1 << 20,
		MaxLineBytes:   4096,
		Timeout:        30 * time.Second,
	})
	f.SetFixtureTLSTrust(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		})
	return f
}

// runPolicyE2ESync drives the real Syncer against the fixture server and returns
// the published matcher plus the sync result. TLS verification is disabled only
// through the fetcher's fixture seam, never by changing production defaults: the
// fetcher is constructed with the fixture's trusted client and the URL is a
// localhost test listener that the SSRF validator would not accept on its own.
func runPolicyE2ESync(settings policy.Settings, store policy.Store, srv *httptest.Server) (*policy.Matcher, policy.SyncResult, error) {
	matcher := policy.NewMatcher()
	fetcher := newFixtureFetcher(srv)
	cfg, err := settings.SyncConfig()
	if err != nil {
		return nil, policy.SyncResult{}, err
	}
	syncer, err := policy.NewSyncer(matcher, fetcher, store, cfg)
	if err != nil {
		return nil, policy.SyncResult{}, err
	}
	res, err := syncer.SyncOnce(context.Background())
	if err != nil {
		return nil, res, err
	}
	return matcher, res, nil
}

func newPolicyE2EService() (*Service, error) {
	return NewVPNService(nil, nil)
}

// activatePolicyE2E runs the production activation entry point the admin PUT
// handler uses. StartPolicyRouting builds its own matcher, syncs, and falls back to
// the durable last-known-good generation when the live fetch cannot complete, so
// callers must not pre-seed a matcher (doing so would be silently discarded).
func activatePolicyE2E(svc *Service, settings policy.Settings, store policy.Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return svc.StartPolicyRouting(ctx, settings, store, string(settings.Preset))
}
