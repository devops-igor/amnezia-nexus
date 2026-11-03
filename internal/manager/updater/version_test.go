package updater

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantSegs   []int
		wantPre    string
		wantBuild  string
		wantMajor  int
		wantMinor  int
		wantPatch  int
	}{
		{
			name:      "standard 3 segments with v prefix",
			input:     "v1.8.24",
			wantErr:   false,
			wantSegs:  []int{1, 8, 24},
			wantMajor: 1,
			wantMinor: 8,
			wantPatch: 24,
		},
		{
			name:      "standard 3 segments without prefix",
			input:     "1.8.24",
			wantErr:   false,
			wantSegs:  []int{1, 8, 24},
			wantMajor: 1,
			wantMinor: 8,
			wantPatch: 24,
		},
		{
			name:      "uppercase V prefix",
			input:     "V26.10.29",
			wantErr:   false,
			wantSegs:  []int{26, 10, 29},
			wantMajor: 26,
			wantMinor: 10,
			wantPatch: 29,
		},
		{
			name:      "date tag with leading zeros",
			input:     "v26.10.09",
			wantErr:   false,
			wantSegs:  []int{26, 10, 9},
			wantMajor: 26,
			wantMinor: 10,
			wantPatch: 9,
		},
		{
			name:      "two segments",
			input:     "v2.8",
			wantErr:   false,
			wantSegs:  []int{2, 8},
			wantMajor: 2,
			wantMinor: 8,
			wantPatch: 0,
		},
		{
			name:      "single segment",
			input:     "v3",
			wantErr:   false,
			wantSegs:  []int{3},
			wantMajor: 3,
			wantMinor: 0,
			wantPatch: 0,
		},
		{
			name:      "multi-segment chromium style with prerelease/revision",
			input:     "v154.0.8037.49-5",
			wantErr:   false,
			wantSegs:  []int{154, 0, 8037, 49},
			wantPre:   "5",
			wantMajor: 154,
			wantMinor: 0,
			wantPatch: 8037,
		},
		{
			name:      "prerelease rc",
			input:     "v1.12.0-rc1",
			wantErr:   false,
			wantSegs:  []int{1, 12, 0},
			wantPre:   "rc1",
			wantMajor: 1,
			wantMinor: 12,
			wantPatch: 0,
		},
		{
			name:      "prerelease with dots and build metadata",
			input:     "1.0.0-beta.2+build.20261103",
			wantErr:   false,
			wantSegs:  []int{1, 0, 0},
			wantPre:   "beta.2",
			wantBuild: "build.20261103",
			wantMajor: 1,
			wantMinor: 0,
			wantPatch: 0,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "only v",
			input:   "v",
			wantErr: true,
		},
		{
			name:    "only V",
			input:   "V",
			wantErr: true,
		},
		{
			name:    "non-numeric segments",
			input:   "v1.x.3",
			wantErr: true,
		},
		{
			name:    "empty segment between dots",
			input:   "1..3",
			wantErr: true,
		},
		{
			name:    "alpha string only",
			input:   "beta",
			wantErr: true,
		},
		{
			name:    "negative segment",
			input:   "1.-2.3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseVersion(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(v.Segments) != len(tt.wantSegs) {
				t.Fatalf("ParseVersion(%q) Segments = %v, want %v", tt.input, v.Segments, tt.wantSegs)
			}
			for i := range v.Segments {
				if v.Segments[i] != tt.wantSegs[i] {
					t.Errorf("ParseVersion(%q) Segments[%d] = %d, want %d", tt.input, i, v.Segments[i], tt.wantSegs[i])
				}
			}
			if v.Prerelease != tt.wantPre {
				t.Errorf("ParseVersion(%q) Prerelease = %q, want %q", tt.input, v.Prerelease, tt.wantPre)
			}
			if v.Build != tt.wantBuild {
				t.Errorf("ParseVersion(%q) Build = %q, want %q", tt.input, v.Build, tt.wantBuild)
			}
			if v.Major() != tt.wantMajor {
				t.Errorf("ParseVersion(%q) Major() = %d, want %d", tt.input, v.Major(), tt.wantMajor)
			}
			if v.Minor() != tt.wantMinor {
				t.Errorf("ParseVersion(%q) Minor() = %d, want %d", tt.input, v.Minor(), tt.wantMinor)
			}
			if v.Patch() != tt.wantPatch {
				t.Errorf("ParseVersion(%q) Patch() = %d, want %d", tt.input, v.Patch(), tt.wantPatch)
			}
			if v.String() != tt.input {
				t.Errorf("ParseVersion(%q).String() = %q, want %q", tt.input, v.String(), tt.input)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name    string
		v1      string
		v2      string
		want    int
		wantErr bool
	}{
		{
			name: "patch difference newer",
			v1:   "v1.8.24",
			v2:   "v1.8.25",
			want: -1,
		},
		{
			name: "patch difference older",
			v1:   "v1.8.25",
			v2:   "v1.8.24",
			want: 1,
		},
		{
			name: "identical version",
			v1:   "v1.8.24",
			v2:   "v1.8.24",
			want: 0,
		},
		{
			name: "mixed v prefix identical",
			v1:   "1.8.24",
			v2:   "v1.8.24",
			want: 0,
		},
		{
			name: "calver comparison",
			v1:   "v26.10.29",
			v2:   "v26.10.30",
			want: -1,
		},
		{
			name: "calver minor newer",
			v1:   "v26.09.29",
			v2:   "v26.10.01",
			want: -1,
		},
		{
			name: "implicit zero patch equality",
			v1:   "1.8",
			v2:   "1.8.0",
			want: 0,
		},
		{
			name: "prerelease vs normal release (prerelease is older)",
			v1:   "v1.12.0-rc1",
			v2:   "v1.12.0",
			want: -1,
		},
		{
			name: "normal release vs prerelease (normal is newer)",
			v1:   "v1.12.0",
			v2:   "v1.12.0-rc1",
			want: 1,
		},
		{
			name: "prerelease rc numeric comparison",
			v1:   "v1.12.0-rc1",
			v2:   "v1.12.0-rc2",
			want: -1,
		},
		{
			name: "prerelease rc1 vs rc10 numeric precedence",
			v1:   "v1.12.0-rc1",
			v2:   "v1.12.0-rc10",
			want: -1,
		},
		{
			name: "prerelease dot numeric comparison rc.1 vs rc.10",
			v1:   "v1.12.0-rc.1",
			v2:   "v1.12.0-rc.10",
			want: -1,
		},
		{
			name: "prerelease alpha vs beta",
			v1:   "v1.0.0-alpha",
			v2:   "v1.0.0-beta",
			want: -1,
		},
		{
			name: "prerelease numeric vs non-numeric",
			v1:   "v1.0.0-1",
			v2:   "v1.0.0-alpha",
			want: -1,
		},
		{
			name: "prerelease segment count difference",
			v1:   "v1.0.0-alpha",
			v2:   "v1.0.0-alpha.1",
			want: -1,
		},
		{
			name: "multi-segment chromium version comparison",
			v1:   "v154.0.8037.49-1",
			v2:   "v154.0.8037.49-5",
			want: -1,
		},
		{
			name: "multi-segment chromium newer patch",
			v1:   "v154.0.8037.49-5",
			v2:   "v154.0.8037.50-1",
			want: -1,
		},
		{
			name: "build metadata ignored for precedence",
			v1:   "1.0.0+build1",
			v2:   "1.0.0+build2",
			want: 0,
		},
		{
			name:    "invalid first version",
			v1:      "invalid",
			v2:      "1.0.0",
			wantErr: true,
		},
		{
			name:    "invalid second version",
			v1:      "1.0.0",
			v2:      "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compare(tt.v1, tt.v2)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Compare(%q, %q) err = %v, wantErr %v", tt.v1, tt.v2, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestIsUpdateAvailable(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		latest    string
		want      bool
	}{
		{
			name:      "strictly newer version available",
			installed: "v1.8.24",
			latest:    "v1.8.25",
			want:      true,
		},
		{
			name:      "calver update available",
			installed: "v26.10.29",
			latest:    "v26.10.30",
			want:      true,
		},
		{
			name:      "rc to full release update available",
			installed: "v1.12.0-rc1",
			latest:    "v1.12.0",
			want:      true,
		},
		{
			name:      "rc1 to rc2 update available",
			installed: "v1.12.0-rc1",
			latest:    "v1.12.0-rc2",
			want:      true,
		},
		{
			name:      "multi-segment chromium update available",
			installed: "v154.0.8037.49-1",
			latest:    "v154.0.8037.49-5",
			want:      true,
		},
		{
			name:      "installed equals latest",
			installed: "v1.8.24",
			latest:    "v1.8.24",
			want:      false,
		},
		{
			name:      "installed is newer than latest (dev build / rollback)",
			installed: "v1.8.25",
			latest:    "v1.8.24",
			want:      false,
		},
		{
			name:      "installed is full release, latest is rc",
			installed: "v1.12.0",
			latest:    "v1.12.0-rc1",
			want:      false,
		},
		{
			name:      "malformed installed version",
			installed: "unknown",
			latest:    "v1.8.25",
			want:      false,
		},
		{
			name:      "empty installed version",
			installed: "",
			latest:    "v1.8.25",
			want:      false,
		},
		{
			name:      "malformed latest version",
			installed: "v1.8.24",
			latest:    "broken-tag",
			want:      false,
		},
		{
			name:      "both malformed",
			installed: "none",
			latest:    "none",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsUpdateAvailable(tt.installed, tt.latest)
			if got != tt.want {
				t.Errorf("IsUpdateAvailable(%q, %q) = %v, want %v", tt.installed, tt.latest, got, tt.want)
			}
		})
	}
}
