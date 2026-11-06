//go:build linux

package vpn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// This file is the fixture half of the issue-678 remedy. It provides the test's
// own prerequisite isolation plus the direct readbacks that make a failure
// actionable.
//
// Why it is needed, from evidence/namespace-readback-ci/test-job.log (run
// 42279016931 at 469b704): the job container mounts `/proc` rw but `/proc/sys`
// as a separate read-only mount (`proc=rw proc_sys=ro`), so the fixture's
// `ip netns exec <ns> sysctl -w` preparation could not make its prerequisites
// true, while still exiting 0. A utility that exits 0 is not evidence that the
// value is visible to the process whose `/proc/sys` view the production guard
// reads. The run failed at the boundary with `accept_local=0` and activation was
// never attempted.
//
// The remedy is test-only and uses the capabilities CI already grants (SYS_ADMIN
// for the mount namespace, plus NET_ADMIN/NET_RAW and /dev/net/tun as before):
// the disposable activation child unshares a private mount namespace, makes its
// propagation private and verifies that BEFORE mounting, then mounts a fresh
// procfs over /proc in that namespace. A procfs superblock is bound to the
// network namespace of the process that mounts it, so the child's own writes and
// the production guard's reads address the same per-namespace keys — the
// prerequisite becomes genuinely true instead of being injected.
//
// Nothing here touches the container's mount table, the host procfs, a host
// sysctl, the production guards or the production constructor, and no step is
// skipped in CI: every unmet step is a hard failure that names its class.
//
// The child also locks its OS thread around the whole privileged section. A mount
// namespace is per-thread, so the fresh procfs is only visible on the thread that
// mounted it; locking keeps the synchronous production prerequisite reads on that
// thread instead of letting them resolve to another thread's mount view.

const (
	// policyE2EProcfsPath is the only mount target this fixture uses. It lives
	// inside the child's private mount namespace, so it is that child's own view
	// and never the container's or the host's mount table.
	policyE2EProcfsPath = "/proc"
	// policyE2ESysctlRoot is the prerequisite root the production guard reads.
	policyE2ESysctlRoot = "/proc/sys"
	// policyE2EWANDevice is the device name production creates and configures
	// per-device accept_local on (internal/vpn/wan_device_linux.go).
	policyE2EWANDevice = "nexus-wan0"
	// policyE2ENotApplied is the class of a prerequisite that read back a
	// different value from the one written.
	policyE2ENotApplied = "value-not-applied"
	// policyE2ENotPrivate is the class of a mount table that does not show the
	// root mount as private, so mounting into it could propagate outwards.
	policyE2ENotPrivate = "propagation-not-private"
)

// policyE2EPrerequisite is one kernel prerequisite the production guard requires,
// with the exact value it compares against.
type policyE2EPrerequisite struct {
	rel   string // path below /proc/sys; a fixed literal, never logged as a path
	value string
}

// policyE2EPrerequisites lists what ValidateKernelPrerequisites requires of the
// namespace this fixture prepares. rp_filter uses loose mode (2) because the
// guard rejects only strict mode (1).
func policyE2EPrerequisites() []policyE2EPrerequisite {
	return []policyE2EPrerequisite{
		{rel: "net/ipv4/ip_forward", value: "1"},
		{rel: "net/ipv4/conf/all/rp_filter", value: "2"},
		{rel: "net/ipv4/conf/all/accept_local", value: "1"},
	}
}

// policyE2EMountOps is the seam over the syscalls the isolation needs, so the
// sequence and every abort path can be exercised without a capability or a mount.
type policyE2EMountOps struct {
	Unshare   func(flags int) error
	Mount     func(source, target, fstype string, flags uintptr, data string) error
	Unmount   func(target string, flags int) error
	MountInfo func() ([]byte, error)
}

func realPolicyE2EMountOps() policyE2EMountOps {
	return policyE2EMountOps{
		Unshare: unix.Unshare,
		Mount: func(source, target, fstype string, flags uintptr, data string) error {
			return unix.Mount(source, target, fstype, flags, data)
		},
		Unmount: unix.Unmount,
		MountInfo: func() ([]byte, error) {
			// #nosec G304 -- fixed kernel mount table path
			return os.ReadFile("/proc/self/mountinfo")
		},
	}
}

// enterPolicyE2EPrivateProcfs isolates the calling thread's mount namespace,
// mounts a fresh procfs over /proc and returns the cleanup that removes it.
//
// Order is load-bearing. The mount namespace is unshared, its propagation is made
// private and that is verified BEFORE anything is mounted, so no mount this
// fixture performs can propagate to the container or the runner host. A failure
// before the procfs mount returns a classified error and no cleanup; the caller
// only ever runs cleanup for a mount that actually happened.
func enterPolicyE2EPrivateProcfs(ops policyE2EMountOps) (func(), error) {
	if err := ops.Unshare(unix.CLONE_NEWNS); err != nil {
		return nil, fmt.Errorf("unshare private mount namespace: %s", classifyPolicyE2ESyscallFailure(err))
	}
	if err := ops.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("isolate mount propagation: %s", classifyPolicyE2ESyscallFailure(err))
	}
	mountinfo, err := ops.MountInfo()
	if err != nil {
		return nil, fmt.Errorf("verify mount propagation: read mount table: %s", classifyPolicyE2ESyscallFailure(err))
	}
	if !rootMountIsPrivate(mountinfo) {
		return nil, fmt.Errorf("verify mount propagation: %s", policyE2ENotPrivate)
	}
	if err := ops.Mount("proc", policyE2EProcfsPath, "proc", 0, ""); err != nil {
		return nil, fmt.Errorf("mount private procfs: %s", classifyPolicyE2ESyscallFailure(err))
	}
	return func() {
		// Detach is best effort: the private mount namespace is destroyed when
		// this process exits, which is the backstop if the explicit detach fails.
		_ = ops.Unmount(policyE2EProcfsPath, unix.MNT_DETACH)
	}, nil
}

// rootMountIsPrivate reports whether the mount table shows the root mount as
// neither shared nor a slave of another mount. Only a private root guarantees
// that a mount made here cannot propagate outwards.
func rootMountIsPrivate(mountinfo []byte) bool {
	for _, line := range strings.Split(string(mountinfo), "\n") {
		left, _, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) < 6 || fields[4] != "/" {
			continue
		}
		// Optional fields start after: id, parent, major:minor, root, mountpoint,
		// mount options. "shared:" and "master:" are the propagation peer fields.
		for _, opt := range fields[6:] {
			if strings.HasPrefix(opt, "shared:") || strings.HasPrefix(opt, "master:") {
				return false
			}
		}
		return true
	}
	return false
}

// applyPolicyE2EPrerequisites makes the production guard's prerequisites true for
// this process's view and verifies each by reading it back through the same
// key the guard reads. root is /proc/sys at the call site and a temporary
// directory in the offline control.
func applyPolicyE2EPrerequisites(root string) error {
	for _, prereq := range policyE2EPrerequisites() {
		path := filepath.Join(root, prereq.rel)
		// #nosec G304 -- fixed procfs keys under a controlled root
		if err := os.WriteFile(path, []byte(prereq.value+"\n"), 0o600); err != nil {
			return fmt.Errorf("write %s: %s", prereq.rel, classifyPolicyE2ESyscallFailure(err))
		}
		// #nosec G304 -- fixed procfs keys under a controlled root
		got, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read back %s: %s", prereq.rel, classifyPolicyE2ESyscallFailure(err))
		}
		if strings.TrimSpace(string(got)) != prereq.value {
			return fmt.Errorf("read back %s: %s", prereq.rel, policyE2ENotApplied)
		}
	}
	return nil
}

// classifyPolicyE2ESyscallFailure names the class of a mount or procfs failure so
// a missing privilege is distinguishable from a read-only mount or a missing key
// without recording arbitrary error text.
func classifyPolicyE2ESyscallFailure(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return "permission-denied"
	case errors.Is(err, unix.EROFS):
		return "read-only-filesystem"
	case errors.Is(err, unix.ENOENT):
		return "missing-key"
	default:
		return "other"
	}
}

// reportPolicyE2EContext renders this process's own prerequisite view as short
// tokens: an unreadable key stays distinguishable from a readable zero, and no
// file content, host path or raw identity can reach a log.
func reportPolicyE2EContext() string {
	return fmt.Sprintf("ip_forward=%s rp_filter=%s accept_local=%s proc=%s proc_sys=%s %s",
		readPolicyE2ENumericValue("/proc/sys/net/ipv4/ip_forward"),
		readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/rp_filter"),
		readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/accept_local"),
		readPolicyE2EMountClass("/proc"),
		readPolicyE2EMountClass("/proc/sys"),
		describePolicyE2EDeviceReadback())
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
// key from a readable value, which is what a guard failure could not say.
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

// describePolicyE2EDeviceReadback reports the per-device key production configures,
// so a guard failure distinguishes a missing interface from an unapplied value.
func describePolicyE2EDeviceReadback() string {
	path := "/proc/sys/net/ipv4/conf/" + policyE2EWANDevice + "/accept_local"
	return "device_accept_local=" + readPolicyE2EDeviceValue(path)
}

// readPolicyE2EMountClass reports whether the mountpoint is read-only, read-write
// or not present. It distinguishes the mount flag from the sysctl value: a
// writable mount and an unchanged value are separate observations.
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
// These prove the isolation sequence, the privacy parser, the classifiers and the
// sanitizers without privileges, a namespace, a container or a mount: the same
// pattern the repository already uses for classifyPrerequisiteOutcome.

// TestPolicyE2EPrivateProcfsIsolationSequence pins the syscall ORDER and every
// abort path of enterPolicyE2EPrivateProcfs. The property that matters is that no
// mount happens before the namespace is unshared and its propagation is verified
// private, so a mount can never reach the container or the host.
func TestPolicyE2EPrivateProcfsIsolationSequence(t *testing.T) {
	const privateTable = "36 35 0:32 / / rw,relatime - overlay overlay rw\n"
	const sharedTable = "36 35 0:32 / / rw,relatime shared:1 - overlay overlay rw\n"

	type recorded struct {
		op   string
		args string
	}
	newOps := func(errs map[string]error, mountinfo string, calls *[]recorded) policyE2EMountOps {
		mount := func(source, target, fstype string, flags uintptr, data string) error {
			*calls = append(*calls, recorded{"mount", fmt.Sprintf("%s|%s|%s|%#x", source, target, fstype, flags)})
			// Injected failures are keyed by mount target: "/" for the propagation
			// change and "/proc" for the procfs mount.
			return errs["mount:"+target]
		}
		return policyE2EMountOps{
			Unshare: func(flags int) error {
				*calls = append(*calls, recorded{"unshare", ""})
				if flags != unix.CLONE_NEWNS {
					*calls = append(*calls, recorded{"unshare-flags-unexpected", fmt.Sprintf("%#x", flags)})
				}
				return errs["unshare"]
			},
			Mount: mount,
			Unmount: func(target string, flags int) error {
				*calls = append(*calls, recorded{"unmount", fmt.Sprintf("%s|%d", target, flags)})
				return nil
			},
			MountInfo: func() ([]byte, error) {
				*calls = append(*calls, recorded{"mountinfo", ""})
				if err := errs["mountinfo"]; err != nil {
					return nil, err
				}
				return []byte(mountinfo), nil
			},
		}
	}

	tests := []struct {
		name       string
		errs       map[string]error
		mountinfo  string
		wantOps    []string
		wantErrSub string
		wantClean  bool
	}{
		{
			name:      "private namespace is established before procfs is mounted",
			mountinfo: privateTable,
			wantOps: []string{
				"unshare",
				"mount|" + "|/||0x44000", // MS_REC|MS_PRIVATE on "/"
				"mountinfo",
				"mount|proc|/proc|proc|0x0",
			},
			wantClean: true,
		},
		{
			name:       "unshare refused aborts before any mount",
			errs:       map[string]error{"unshare": unix.EPERM},
			mountinfo:  privateTable,
			wantOps:    []string{"unshare"},
			wantErrSub: "permission-denied",
		},
		{
			name:       "propagation cannot be made private: no procfs mount",
			errs:       map[string]error{"mount:/": unix.EPERM},
			mountinfo:  privateTable,
			wantOps:    []string{"unshare", "mount|" + "|/||0x44000"},
			wantErrSub: "permission-denied",
		},
		{
			name:       "unreadable mount table aborts before procfs mount",
			errs:       map[string]error{"mountinfo": unix.EACCES},
			mountinfo:  privateTable,
			wantOps:    []string{"unshare", "mount|" + "|/||0x44000", "mountinfo"},
			wantErrSub: "permission-denied",
		},
		{
			name:       "still-shared root aborts before procfs mount",
			mountinfo:  sharedTable,
			wantOps:    []string{"unshare", "mount|" + "|/||0x44000", "mountinfo"},
			wantErrSub: policyE2ENotPrivate,
		},
		{
			name:       "read-only procfs mount is named, not silently accepted",
			errs:       map[string]error{"mount:/proc": unix.EROFS},
			mountinfo:  privateTable,
			wantOps:    []string{"unshare", "mount|" + "|/||0x44000", "mountinfo", "mount|proc|/proc|proc|0x0"},
			wantErrSub: "read-only-filesystem",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []recorded
			cleanup, err := enterPolicyE2EPrivateProcfs(newOps(tc.errs, tc.mountinfo, &calls))

			var gotOps []string
			for _, call := range calls {
				if call.args == "" {
					gotOps = append(gotOps, call.op)
					continue
				}
				gotOps = append(gotOps, call.op+"|"+call.args)
			}
			if strings.Join(gotOps, ",") != strings.Join(tc.wantOps, ",") {
				t.Fatalf("syscall order = %v, want %v", gotOps, tc.wantOps)
			}
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cleanup == nil {
					t.Fatal("a successful procfs mount must return cleanup")
				}
				cleanup()
				last := calls[len(calls)-1]
				if last.op != "unmount" || last.args != policyE2EProcfsPath+"|"+fmt.Sprint(unix.MNT_DETACH) {
					t.Fatalf("cleanup must detach %s, got %+v", policyE2EProcfsPath, last)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error %q does not name the class %q", err, tc.wantErrSub)
			}
			if cleanup != nil {
				t.Fatal("a failed isolation must not return cleanup for a mount that never happened")
			}
			for _, call := range calls {
				if call.op == "unmount" {
					t.Fatalf("nothing was mounted, so nothing should be unmounted: %+v", call)
				}
			}
		})
	}
}

func TestPolicyE2ERootMountIsPrivate(t *testing.T) {
	tests := []struct {
		name      string
		mountinfo string
		want      bool
	}{
		{
			name:      "private root",
			mountinfo: "36 35 0:32 / / rw,relatime - overlay overlay rw\n",
			want:      true,
		},
		{
			name:      "shared root would propagate outwards",
			mountinfo: "36 35 0:32 / / rw,relatime shared:1 - overlay overlay rw\n",
			want:      false,
		},
		{
			name:      "slave root would still receive propagation",
			mountinfo: "36 35 0:32 / / rw,relatime master:1 - overlay overlay rw\n",
			want:      false,
		},
		{
			name: "only the root mount counts",
			mountinfo: "36 35 0:32 / /proc rw,relatime shared:7 - proc proc rw\n" +
				"37 36 0:33 / / rw,relatime - overlay overlay rw\n",
			want: true,
		},
		{
			name:      "no root mount in the table is not private",
			mountinfo: "36 35 0:32 / /proc rw,relatime - proc proc rw\n",
			want:      false,
		},
		{
			name:      "empty table is not private",
			mountinfo: "",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rootMountIsPrivate([]byte(tc.mountinfo)); got != tc.want {
				t.Fatalf("rootMountIsPrivate() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPolicyE2ESyscallFailureClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"no error", nil, "none"},
		{"operation not permitted", unix.EPERM, "permission-denied"},
		{"permission denied", unix.EACCES, "permission-denied"},
		{"read-only mount", unix.EROFS, "read-only-filesystem"},
		{"missing key", unix.ENOENT, "missing-key"},
		{"wrapped read-only mount", fmt.Errorf("mount: %w", unix.EROFS), "read-only-filesystem"},
		{"unclassified", errors.New("boom"), "other"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPolicyE2ESyscallFailure(tc.err); got != tc.want {
				t.Fatalf("classifyPolicyE2ESyscallFailure(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestPolicyE2EPrerequisiteApplication proves the write-then-read-back contract
// against a temporary root: every listed key must be verified from the same path
// the production guard reads, and an unwritable root must fail closed instead of
// reporting preparation success.
func TestPolicyE2EPrerequisiteApplication(t *testing.T) {
	root := t.TempDir()
	for _, prereq := range policyE2EPrerequisites() {
		dir := filepath.Join(root, filepath.Dir(prereq.rel))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create key directory: %v", err)
		}
	}
	if err := applyPolicyE2EPrerequisites(root); err != nil {
		t.Fatalf("applyPolicyE2EPrerequisites() = %v, want nil", err)
	}
	for _, prereq := range policyE2EPrerequisites() {
		data, err := os.ReadFile(filepath.Join(root, prereq.rel))
		if err != nil {
			t.Fatalf("read back %s: %v", prereq.rel, err)
		}
		if strings.TrimSpace(string(data)) != prereq.value {
			t.Fatalf("%s = %q, want %q", prereq.rel, strings.TrimSpace(string(data)), prereq.value)
		}
	}

	// A missing key directory must be a classified failure, never a silent pass:
	// this is the exact shape of a preparation that does not take effect.
	err := applyPolicyE2EPrerequisites(t.TempDir())
	if err == nil {
		t.Fatal("expected a failure when the prerequisite keys do not exist")
	}
	if !strings.Contains(err.Error(), "missing-key") {
		t.Fatalf("error %q must name the missing-key class", err)
	}
}

// TestPolicyE2ERealContextReadback exercises the reading path against this
// process's real /proc (no namespace, no privileges, no write) and asserts only
// that every field is a token the readers can emit. It proves the readback cannot
// print arbitrary file content, not that any prerequisite is satisfied.
func TestPolicyE2ERealContextReadback(t *testing.T) {
	allowed := map[string][]string{
		"ip_forward":   {"0", "1", "other", "unreadable"},
		"rp_filter":    {"0", "1", "2", "other", "unreadable"},
		"accept_local": {"0", "1", "other", "unreadable"},
		"proc":         {"ro", "rw", "absent", "unknown"},
		"proc_sys":     {"ro", "rw", "absent", "unknown"},
	}
	got := map[string]string{
		"ip_forward":   readPolicyE2ENumericValue("/proc/sys/net/ipv4/ip_forward"),
		"rp_filter":    readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/rp_filter"),
		"accept_local": readPolicyE2ENumericValue("/proc/sys/net/ipv4/conf/all/accept_local"),
		"proc":         readPolicyE2EMountClass("/proc"),
		"proc_sys":     readPolicyE2EMountClass("/proc/sys"),
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
	if got["proc"] == "unknown" {
		t.Logf("note: /proc mount class unavailable in this environment")
	}
	// The report form must stay token-only: no path and no raw identity.
	if report := reportPolicyE2EContext(); strings.Contains(report, "/proc") {
		t.Fatalf("report leaked a host path: %q", report)
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
		t.Fatalf("unclassified error class = %q, want \"other\"", got)
	}
}
