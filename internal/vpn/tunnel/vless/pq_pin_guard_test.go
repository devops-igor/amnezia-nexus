package vless

import (
	"strings"
	"testing"
)

// withdrawnModernDigest is the multi-arch manifest list digest of Xray-core 26.10.29, which
// upstream retracted after an IPv4 MPTCP local-privilege-escalation advisory. Upstream deleted
// the release and the GHCR manifest together with the digest, so a pull of this reference now
// fails with MANIFEST_UNKNOWN — that is the exact failure this repair corrects.
const withdrawnModernDigest = "sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044"

// TestPinnedModernImageIsNotWithdrawn pins the anti-regression properties of the modern fixture
// pin. TestPinnedImageDigests only compares constants to literals and therefore cannot detect an
// upstream withdrawal: it stayed green while the 26.10.29 manifest was already returning 404.
//
// These checks fail for the defect class rather than restating the pin: reintroducing the
// retracted digest, drifting to a mutable tag, or dropping the digest pin entirely.
func TestPinnedModernImageIsNotWithdrawn(t *testing.T) {
	if pinnedModernDigest == withdrawnModernDigest {
		t.Fatalf("pinned modern digest is the withdrawn 26.10.29 digest %q; pulls will fail with MANIFEST_UNKNOWN", withdrawnModernDigest)
	}
	if strings.Contains(pinnedModernImage, withdrawnModernDigest) {
		t.Errorf("pinned modern image %q still embeds the withdrawn digest %q", pinnedModernImage, withdrawnModernDigest)
	}
	if strings.Contains(pinnedModernImage, ":26.10.29@") {
		t.Errorf("pinned modern image %q still targets the retracted 26.10.29 tag", pinnedModernImage)
	}
}

// TestPinnedImagesAreImmutable verifies both container fixtures stay tag-and-digest pinned.
// A bare tag (or "latest") would let upstream substitution silently change the engine build
// under test, and a bare digest would lose the human-readable version.
func TestPinnedImagesAreImmutable(t *testing.T) {
	tests := []struct {
		name  string
		image string
		tag   string
	}{
		{name: "legacy fixture", image: pinnedLegacyImage, tag: "1.8.24"},
		{name: "modern fixture", image: pinnedModernImage, tag: "26.10.31"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.image == "" {
				t.Fatalf("%s image is empty", tc.name)
			}
			wantPrefix := "ghcr.io/xtls/xray-core:" + tc.tag + "@sha256:"
			if !strings.HasPrefix(tc.image, wantPrefix) {
				t.Errorf("%s image %q is not pinned as %q", tc.name, tc.image, wantPrefix)
			}
			if strings.Contains(tc.image, "latest") {
				t.Errorf("%s image %q must not use the mutable latest tag", tc.name, tc.image)
			}
			if strings.HasSuffix(tc.image, "@") || !strings.Contains(tc.image, "@sha256:") {
				t.Errorf("%s image %q is missing an immutable digest pin", tc.name, tc.image)
			}
		})
	}
}
