//go:build linux

package vpn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the red/green oracle for the fail-closed source-validation
// prerequisite (#677 F1). Every assertion runs against the real production
// consumers — validateKernelPrerequisitesForDevice, which ValidateKernelPrerequisites
// calls, and validateDirectEgressSourceValidation — not against a reimplementation.

// writeSysctlTree materialises a synthetic /proc/sys skeleton so the real resolver
// can be driven through every effective-value combination without touching the host.
func writeSysctlTree(t *testing.T, all, def map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for _, scope := range []string{"all", "default"} {
		dir := filepath.Join(root, "net/ipv4/conf", scope)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	values := map[string]map[string]string{"all": all, "default": def}
	for scope, kv := range values {
		for key, value := range kv {
			path := filepath.Join(root, "net/ipv4/conf", scope, key)
			if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}
	}
	return root
}

// writeDeviceSysctlTree adds a live per-device directory, standing in for a device
// that already exists.
func writeDeviceSysctlTree(t *testing.T, dev string, all, def, device map[string]string) string {
	t.Helper()
	root := writeSysctlTree(t, all, def)
	dir := filepath.Join(root, "net/ipv4/conf", dev)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for key, value := range device {
		path := filepath.Join(dir, key)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root
}

// TestValidateDirectEgressSourceValidation_EffectiveMatrix pins the kernel's
// composition rules (IN_DEV_MAXCONF for rp_filter, IN_DEV_ORCONF for accept_local)
// and the accept/reject boundary. The documented deployment (all=2, default=2) must
// be REJECTED, and the working configuration (all=0, default=0) accepted: that pair
// is the measured red/green result this gate exists to encode.
func TestValidateDirectEgressSourceValidation_EffectiveMatrix(t *testing.T) {
	const dev = defaultWANTunnelDeviceName

	cases := []struct {
		name    string
		all     string
		def     string
		wantErr bool
		why     string
	}{
		{"documented_deployment_rejected", "2", "2", true, "all=2 default=2 is what README prescribes; effective max is 2 and direct egress forwards nothing"},
		{"strict_rejected", "1", "1", true, "strict filtering drops the locally sourced packet"},
		{"all_zero_default_two_rejected", "0", "2", true, "max(all,default)=2: clearing only conf/all cannot loosen the per-device value"},
		{"all_two_default_zero_rejected", "2", "0", true, "max(all,default)=2: clearing only conf/default cannot loosen conf/all"},
		{"working_configuration_accepted", "0", "0", false, "effective 0 was measured to forward and receive real replies"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeSysctlTree(t,
				map[string]string{"rp_filter": tc.all},
				map[string]string{"rp_filter": tc.def})

			err := validateDirectEgressSourceValidation(root, dev)
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection (%s), got nil", tc.why)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance (%s), got: %v", tc.why, err)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrHostWANSourceValidation) {
					t.Fatalf("error must wrap ErrHostWANSourceValidation, got: %v", err)
				}
				// The error must be actionable: it has to name the setting to change.
				for _, want := range []string{"rp_filter", "conf/all", dev} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q must mention %q to be actionable", err.Error(), want)
					}
				}
			}
		})
	}
}

// TestValidateDirectEgressSourceValidation_LiveDeviceOverridesDefault proves the
// resolver reads a device that already exists instead of conf/default, so the check
// reports the value the interface actually carries.
func TestValidateDirectEgressSourceValidation_LiveDeviceOverridesDefault(t *testing.T) {
	const dev = "nexus-wan-live"

	// default would pass, but the live device is strict: must be rejected.
	root := writeDeviceSysctlTree(t,
		dev,
		map[string]string{"rp_filter": "0"},
		map[string]string{"rp_filter": "0"},
		map[string]string{"rp_filter": "1"})
	err := validateDirectEgressSourceValidation(root, dev)
	if err == nil {
		t.Fatal("expected rejection from a live device carrying rp_filter=1")
	}
	if !strings.Contains(err.Error(), dev) {
		t.Fatalf("error must name the live device %q, got: %v", dev, err)
	}

	// default would fail, but the live device is 0 and it is the live value that counts.
	root = writeDeviceSysctlTree(t,
		dev,
		map[string]string{"rp_filter": "0"},
		map[string]string{"rp_filter": "2"},
		map[string]string{"rp_filter": "0"})
	if err := validateDirectEgressSourceValidation(root, dev); err != nil {
		t.Fatalf("expected acceptance from a live device carrying rp_filter=0, got: %v", err)
	}
}

// TestValidateDirectEgressSourceValidation_UnreadableProcfsIsNotARejection pins the
// tolerance boundary: an unreadable procfs is an environment property, not a proven
// misconfiguration, so it must not fabricate a failure.
func TestValidateDirectEgressSourceValidation_UnreadableProcfsIsNotARejection(t *testing.T) {
	empty := t.TempDir()
	if err := validateDirectEgressSourceValidation(empty, defaultWANTunnelDeviceName); err != nil {
		t.Fatalf("unreadable sysctl tree must not be reported as an incompatible configuration, got: %v", err)
	}
}

// TestProductionStartup_RejectsDocumentedRpFilter is the production-consumer
// counterexample: the real startup validator, reached through the real
// validateKernelPrerequisitesForDevice with a production device name, must refuse the
// documented configuration and must not silently proceed.
func TestProductionStartup_RejectsDocumentedRpFilter(t *testing.T) {
	const dev = defaultWANTunnelDeviceName

	// Redirect the production sysctl root at a synthetic tree describing the
	// documented deployment. ip_forward comes from the real host, so seed this case
	// only for the source-validation stage by calling the device validator directly
	// after asserting the wiring keeps the check in the chain position it occupies.
	root := writeSysctlTree(t,
		map[string]string{"rp_filter": "2"},
		map[string]string{"rp_filter": "2"})

	original := sourceValidationRoot
	sourceValidationRoot = root
	t.Cleanup(func() { sourceValidationRoot = original })

	err := validateKernelPrerequisitesForDevice(dev)
	if err == nil {
		t.Fatal("production startup validation accepted the documented rp_filter=2 configuration")
	}
	if !errors.Is(err, ErrHostWANSourceValidation) {
		t.Fatalf("expected ErrHostWANSourceValidation from the production chain, got: %v", err)
	}
}

// TestProductionStartup_AcceptsWorkingRpFilter proves the same production chain does
// not reject a working configuration for a source-validation reason, so the fix is a
// reject-only guard rather than a blanket refusal. The remaining prerequisites may
// still fail for genuine environment reasons; only a source-validation rejection is
// forbidden here.
func TestProductionStartup_AcceptsWorkingRpFilter(t *testing.T) {
	const dev = defaultWANTunnelDeviceName

	root := writeSysctlTree(t,
		map[string]string{"rp_filter": "0"},
		map[string]string{"rp_filter": "0"})
	original := sourceValidationRoot
	sourceValidationRoot = root
	t.Cleanup(func() { sourceValidationRoot = original })

	err := validateKernelPrerequisitesForDevice(dev)
	if errors.Is(err, ErrHostWANSourceValidation) {
		t.Fatalf("working rp_filter=0 configuration was rejected by source validation: %v", err)
	}
}

// TestValidateKernelPrerequisites_DefaultDeviceName pins that the exported entry
// point validates the device the production constructor actually creates, so the two
// cannot drift apart.
func TestValidateKernelPrerequisites_DefaultDeviceName(t *testing.T) {
	if defaultWANTunnelDeviceName != "nexus-wan0" {
		t.Fatalf("production WAN tunnel device name changed to %q; NewProductionWANDevice and the PBR composition root use \"nexus-wan0\" consistently — update both or the prerequisite is validated for the wrong interface", defaultWANTunnelDeviceName)
	}
}
