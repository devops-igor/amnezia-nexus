package updater

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed semantic or multi-segment version.
type Version struct {
	Original   string
	Segments   []int
	Prerelease string
	Build      string
}

// Major returns the first version segment, or 0 if empty.
func (v *Version) Major() int {
	if len(v.Segments) > 0 {
		return v.Segments[0]
	}
	return 0
}

// Minor returns the second version segment, or 0 if empty.
func (v *Version) Minor() int {
	if len(v.Segments) > 1 {
		return v.Segments[1]
	}
	return 0
}

// Patch returns the third version segment, or 0 if empty.
func (v *Version) Patch() int {
	if len(v.Segments) > 2 {
		return v.Segments[2]
	}
	return 0
}

// String returns the original version string.
func (v *Version) String() string {
	return v.Original
}

// ParseVersion parses a version string into a Version struct.
// It supports standard SemVer (e.g. v1.8.24, v1.12.0-rc1), CalVer (e.g. v26.10.29),
// and multi-segment versions (e.g. v154.0.8037.49-5). Optional leading 'v' or 'V' is stripped.
func ParseVersion(raw string) (*Version, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty version string")
	}

	// Strip optional leading 'v' or 'V'
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return nil, errors.New("version string has no numeric component")
	}

	v := &Version{
		Original: raw,
	}

	// Extract build metadata (after '+')
	if plusIdx := strings.IndexByte(s, '+'); plusIdx != -1 {
		v.Build = s[plusIdx+1:]
		s = s[:plusIdx]
	}

	// Extract prerelease (after the first '-')
	if hyphenIdx := strings.IndexByte(s, '-'); hyphenIdx != -1 {
		v.Prerelease = s[hyphenIdx+1:]
		s = s[:hyphenIdx]
	}

	if s == "" {
		return nil, errors.New("version string missing core numeric segments")
	}

	// Parse numeric dot-separated segments
	parts := strings.Split(s, ".")
	v.Segments = make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty segment in version %q", raw)
		}
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 {
			return nil, fmt.Errorf("invalid numeric segment %q in version %q", part, raw)
		}
		v.Segments = append(v.Segments, num)
	}

	return v, nil
}

// CompareVersions compares two parsed versions following SemVer 2.0.0 precedence rules.
// Returns:
//
//	-1 if v1 < v2
//	 0 if v1 == v2
//	 1 if v1 > v2
func CompareVersions(v1, v2 *Version) int {
	maxLen := len(v1.Segments)
	if len(v2.Segments) > maxLen {
		maxLen = len(v2.Segments)
	}

	// 1. Compare numeric segments sequentially
	for i := 0; i < maxLen; i++ {
		seg1 := 0
		if i < len(v1.Segments) {
			seg1 = v1.Segments[i]
		}
		seg2 := 0
		if i < len(v2.Segments) {
			seg2 = v2.Segments[i]
		}
		if seg1 < seg2 {
			return -1
		}
		if seg1 > seg2 {
			return 1
		}
	}

	// 2. Compare prerelease precedence
	// A normal version has greater precedence than a prerelease version.
	if v1.Prerelease == "" && v2.Prerelease != "" {
		return 1
	}
	if v1.Prerelease != "" && v2.Prerelease == "" {
		return -1
	}
	if v1.Prerelease == "" && v2.Prerelease == "" {
		return 0
	}

	// Both have prereleases
	return comparePrereleases(v1.Prerelease, v2.Prerelease)
}

// comparePrereleases compares two prerelease identifiers per SemVer 2.0.0 rules.
func comparePrereleases(p1, p2 string) int {
	parts1 := strings.Split(p1, ".")
	parts2 := strings.Split(p2, ".")

	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		id1 := parts1[i]
		id2 := parts2[i]
		if id1 == id2 {
			continue
		}

		n1, err1 := strconv.Atoi(id1)
		n2, err2 := strconv.Atoi(id2)

		// Both numeric: compare numerically
		if err1 == nil && err2 == nil {
			if n1 < n2 {
				return -1
			}
			return 1
		}

		// Numeric has lower precedence than non-numeric
		if err1 == nil && err2 != nil {
			return -1
		}
		if err1 != nil && err2 == nil {
			return 1
		}

		// Lexical comparison in ASCII order per SemVer 2.0.0
		if id1 < id2 {
			return -1
		}
		return 1
	}

	// A larger set of pre-release fields has a higher precedence
	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

// Compare parses and compares two version strings.
// Returns:
//
//	-1 if v1 < v2
//	 0 if v1 == v2
//	 1 if v1 > v2
//	error if either version is invalid.
func Compare(raw1, raw2 string) (int, error) {
	v1, err := ParseVersion(raw1)
	if err != nil {
		return 0, fmt.Errorf("invalid version 1 %q: %w", raw1, err)
	}
	v2, err := ParseVersion(raw2)
	if err != nil {
		return 0, fmt.Errorf("invalid version 2 %q: %w", raw2, err)
	}
	return CompareVersions(v1, v2), nil
}

// UpdateStatus represents the status of an update check.
type UpdateStatus string

const (
	UpdateAvailable UpdateStatus = "available"
	UpdateUpToDate  UpdateStatus = "up_to_date"
	UpdateUnknown   UpdateStatus = "unknown"

	// VersionStatus aliases for consistency with review specifications.
	VersionStatusUnknown   = UpdateUnknown
	VersionStatusAvailable = UpdateAvailable
	VersionStatusUpToDate  = UpdateUpToDate
)

// CheckUpdateStatus evaluates whether an update is available between installed and latest versions.
// If installed is empty or unparseable, it returns UpdateUnknown.
// If latest is empty or unparseable, it returns UpdateUnknown.
// If latest is newer than installed, it returns UpdateAvailable.
// If installed >= latest, it returns UpdateUpToDate.
func CheckUpdateStatus(installed, latest string) UpdateStatus {
	vInst, err := ParseVersion(installed)
	if err != nil {
		return UpdateUnknown
	}
	vLat, err := ParseVersion(latest)
	if err != nil {
		return UpdateUnknown
	}
	if CompareVersions(vInst, vLat) < 0 {
		return UpdateAvailable
	}
	return UpdateUpToDate
}

// IsUpdateAvailable returns true if latest is strictly newer than installed.
// It returns false on malformed installed versions or if installed >= latest.
func IsUpdateAvailable(installed, latest string) bool {
	return CheckUpdateStatus(installed, latest) == UpdateAvailable
}
