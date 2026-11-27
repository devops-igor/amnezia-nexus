// Package version is the single definition of the pinned upstream component
// identities that the AWG installer and the upstream monitor must agree on. It
// also reports the amneziawg-go module version the running binary was compiled
// against, so a stale constant can be detected instead of skewing status.
package version

import (
	"runtime/debug"
	"strings"
)

const (
	// AWGGoModulePath is the module path of the AmneziaWG userspace datapath.
	AWGGoModulePath = "github.com/amnezia-vpn/amneziawg-go/v3"

	// PinnedAWGGoVersion is the AmneziaWG release the panel compiles against
	// and compares upstream releases with. It must equal the version required
	// for AWGGoModulePath in go.mod.
	PinnedAWGGoVersion = "v3.1.20261116"

	// PinnedAWGToolsVersion is the pinned amneziawg-tools release.
	PinnedAWGToolsVersion = "v3.1.20260812"

	// DefaultDockerRepo is the image repository that publishes the AmneziaWG
	// userspace base image.
	DefaultDockerRepo = "devopsigor/amneziawg"

	// PinnedAWGImageRevision is the image build revision published under the
	// pinned AmneziaWG source version. It changes only when the image is
	// rebuilt from the same source.
	PinnedAWGImageRevision = "1"

	// PinnedAWGBaseImage is the versioned multiarch (amd64 and arm64) base
	// image used to build AWG backends. It is derived from the pinned source
	// version so the image and the compiled module cannot drift apart.
	// Multiarch is required because backends install on both host
	// architectures, and a versioned tag is required because this image
	// becomes a privileged VPN container on remote hosts.
	PinnedAWGBaseImage = DefaultDockerRepo + ":" + PinnedAWGGoVersion + "-" + PinnedAWGImageRevision
)

// CompiledAWGGoVersion returns the amneziawg-go module version recorded in the
// build metadata of the running binary. It falls back to PinnedAWGGoVersion
// when build metadata is unavailable, when the module did not contribute code
// to the binary, or when the build was made from an unversioned replacement.
func CompiledAWGGoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return PinnedAWGGoVersion
	}
	return awgGoVersionFromModules(info.Deps)
}

// awgGoVersionFromModules selects the amneziawg-go version from build metadata
// dependencies. A module replacement that names a version wins over the
// required version; a replacement by local directory has no version, so the
// pinned constant is reported instead of an unidentifiable build.
func awgGoVersionFromModules(deps []*debug.Module) string {
	for _, dep := range deps {
		if dep == nil || dep.Path != AWGGoModulePath {
			continue
		}
		if dep.Replace != nil {
			if replaced := usableVersion(dep.Replace.Version); replaced != "" {
				return replaced
			}
			return PinnedAWGGoVersion
		}
		if v := usableVersion(dep.Version); v != "" {
			return v
		}
		return PinnedAWGGoVersion
	}
	return PinnedAWGGoVersion
}

func usableVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "(devel)" {
		return ""
	}
	return v
}
