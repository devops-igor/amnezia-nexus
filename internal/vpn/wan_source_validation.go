//go:build linux

package vpn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// This file implements the fail-closed source-validation prerequisite for direct
// WAN egress (#677).
//
// Why a dedicated check exists
// ----------------------------
// The dispatcher source-NATs direct egress to the host WAN address and writes the
// packet into the WAN tunnel device. The packet therefore re-enters the stack
// addressed to a remote host but carrying a source address that is *local to this
// host*, on a non-loopback device. The kernel's source validation rejects exactly
// that shape, so with an incompatible configuration direct egress silently forwards
// nothing: no error at startup, no traffic on the wire, no replies. A fail-closed
// startup check is therefore the only place this can be reported before an operator
// concludes the feature is broken for an unrelated reason.
//
// Effective-value semantics (authoritative, not inferred)
// ------------------------------------------------------
// Taken from the running kernel's own headers
// (include/linux/inetdevice.h) and Documentation/networking/ip-sysctl.rst:
//
//	IN_DEV_RPFILTER(in_dev)     = IN_DEV_MAXCONF(RP_FILTER)
//	                            = max(all.rp_filter, dev.rp_filter)
//	IN_DEV_ACCEPT_LOCAL(in_dev) = IN_DEV_ORCONF(ACCEPT_LOCAL)
//	                            = all.accept_local || dev.accept_local
//	IN_DEV_FORWARD(in_dev)      = dev.forwarding
//
// and from ip-sysctl.rst: "The max value from conf/{all,interface}/rp_filter is
// used when doing source validation on the {interface}."  Consequently configuring
// only `all` cannot loosen the per-device value, and configuring only the device
// cannot loosen `all`.
//
// Only `rp_filter == 0` is accepted, not the commonly recommended 1 or 2:
//   - strict (1) tests the reverse path against the ingress interface;
//   - loose (2) only requires the source to be reachable via *any* interface, which
//     a local address always is — so it does not rescue this packet.
//
// `accept_local` must be effective as well (all OR device), because a local source
// is a martian regardless of the reverse-path result.
//
// The device that matters is the WAN tunnel device the dispatcher writes into. That
// device does not exist when startup validation runs, and a newly created interface
// inherits its per-device `rp_filter`/`accept_local` from `conf/default`; the
// validator therefore evaluates the device that will be created against
// `conf/default`, which is the value the device will actually carry.
//
// This check is deliberately reject-only. It never writes a sysctl, never relaxes
// host-wide source validation, and never changes PBR-off behavior: it reports an
// incompatible configuration with an actionable error and otherwise stays silent.

// ErrHostWANSourceValidation reports a configuration in which direct WAN egress
// cannot forward its source-NATed packets because kernel source validation drops
// them as martians.
var ErrHostWANSourceValidation = errors.New("kernel prerequisite failed: direct WAN egress injects source-NATed packets with a local source address, which kernel source validation drops; set rp_filter=0 and accept_local=1 for both conf/all and the WAN tunnel device")

// sourceValidationSetting is the resolved effective value of one sysctl on the
// device direct egress writes into, together with where the value came from.
type sourceValidationSetting struct {
	// All is the value configured under conf/all.
	All string
	// Device is the value the ingress device will carry (conf/default for a
	// device that has not been created yet, otherwise the live per-device value).
	Device string
	// Source names the procfs file the device value was read from, so an error can
	// tell an operator which setting to change.
	DeviceSource string
	// known is false when the values could not be read; an unreadable procfs is
	// treated as "cannot prove incompatibility" rather than a failure, matching the
	// existing tolerance for read-only /proc/sys mounts and unprivileged probes.
	known bool
}

// parseProcInt reads a single integer sysctl value.
func parseProcInt(path string) (string, bool) {
	// #nosec G304 -- path is a procfs or test-controlled root constructed internally
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	value := strings.TrimSpace(string(data))
	if _, err := strconv.Atoi(value); err != nil {
		return "", false
	}
	return value, true
}

// readSourceValidationSetting resolves the effective rp_filter and accept_local
// inputs for a device named devName. root is the sysctl root ("/proc/sys" in
// production) and may be redirected by tests.
func readSourceValidationSetting(root, devName, key string) sourceValidationSetting {
	allValue, allOK := parseProcInt(filepath.Join(root, "net/ipv4/conf/all", key))

	// A live device carries its own value; a device that does not exist yet will
	// inherit from conf/default.
	devicePath := filepath.Join(root, "net/ipv4/conf", devName, key)
	deviceValue, deviceOK := parseProcInt(devicePath)
	source := devicePath
	if !deviceOK {
		devicePath = filepath.Join(root, "net/ipv4/conf/default", key)
		source = devicePath
		deviceValue, deviceOK = parseProcInt(devicePath)
	}

	return sourceValidationSetting{
		All:          allValue,
		Device:       deviceValue,
		DeviceSource: source,
		known:        allOK && deviceOK,
	}
}

// effectiveValue applies the kernel's composition rule for the given key and
// returns the effective integer. rp_filter uses max(all, device); accept_local uses
// all || device. The caller must have checked known.
func (s sourceValidationSetting) effectiveValue(key string) int {
	allV, _ := strconv.Atoi(s.All)
	devV, _ := strconv.Atoi(s.Device)
	switch key {
	case "rp_filter":
		// IN_DEV_MAXCONF
		if allV > devV {
			return allV
		}
		return devV
	case "accept_local":
		// IN_DEV_ORCONF
		if allV == 1 || devV == 1 {
			return 1
		}
		return 0
	default:
		return devV
	}
}

// sourceValidationRoot is the sysctl root read by the production check. It is a
// variable so tests can point it at a synthetic root without touching the host.
var sourceValidationRoot = "/proc/sys"

// validateDirectEgressSourceValidation reports an error when the effective kernel
// source-validation configuration provably prevents direct WAN egress from
// forwarding, and nil when it is compatible or cannot be determined.
//
// Scope: the reject decision covers `rp_filter` only, deliberately.
//
//   - `rp_filter` is never written by this process, so a non-zero effective value
//     is a real, unfixable-by-the-daemon misconfiguration and is rejected.
//   - `accept_local` *is* configured by the daemon itself (host-wide at startup and
//     per-device when the tunnel device is created). Rejecting it here would reject
//     a configuration the daemon is about to make valid, and disabling/overriding
//     that write is out of scope. The existing per-device failure path in
//     NewProductionWANDevice already fails closed when accept_local can neither be
//     written nor inherited from conf/all; that path is retained unchanged.
//
// It is pure with respect to the system: it only reads procfs.
func validateDirectEgressSourceValidation(root, devName string) error {
	rp := readSourceValidationSetting(root, devName, "rp_filter")
	if !rp.known {
		// Cannot read the settings at all: report nothing rather than guess. Startup
		// already fails closed on the capabilities and route prerequisites, and an
		// unreadable procfs is an environment property, not a proven misconfiguration.
		return nil
	}

	if effectiveRP := rp.effectiveValue("rp_filter"); effectiveRP != 0 {
		return fmt.Errorf(
			"effective rp_filter=%d for %q (max of conf/all=%s and %s=%s): %w",
			effectiveRP, devName, rp.All, filepath.Base(filepath.Dir(rp.DeviceSource)), rp.Device,
			ErrHostWANSourceValidation)
	}
	return nil
}
