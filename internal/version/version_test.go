package version

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// TestPinnedVersionsConsistency fails when the pinned constants and the build
// inputs they describe disagree. Editing go.mod without updating the constants,
// or editing a constant without updating go.mod, fails here instead of
// silently skewing the upstream update status.
func TestPinnedVersionsConsistency(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	goModVersion, ok := requiredVersion(goMod, AWGGoModulePath)
	if !ok {
		t.Fatalf("go.mod does not require %s", AWGGoModulePath)
	}
	if goModVersion != PinnedAWGGoVersion {
		t.Errorf(
			"PinnedAWGGoVersion is %q but go.mod requires %s %q: update both together",
			PinnedAWGGoVersion,
			AWGGoModulePath,
			goModVersion,
		)
	}

	imageRepo, imageTag, ok := splitImage(PinnedAWGBaseImage)
	if !ok {
		t.Fatalf("PinnedAWGBaseImage %q has no tag", PinnedAWGBaseImage)
	}
	if imageRepo != DefaultDockerRepo {
		t.Errorf("PinnedAWGBaseImage repository is %q, want DefaultDockerRepo %q", imageRepo, DefaultDockerRepo)
	}
	revision, found := strings.CutPrefix(imageTag, PinnedAWGGoVersion+"-")
	if !found || revision == "" {
		t.Errorf(
			"PinnedAWGBaseImage tag %q must embed PinnedAWGGoVersion %q plus an image revision",
			imageTag,
			PinnedAWGGoVersion,
		)
	}
}

// TestCompiledAWGGoVersion reports what the runtime detection returns in a
// normal go test build. A test binary only records the modules its linked
// packages use, so an unlinked module legitimately falls back to the pinned
// constant; the panel binary links the datapath and records the real version.
func TestCompiledAWGGoVersion(t *testing.T) {
	recorded := "(not linked in this test binary)"
	if info, ok := debug.ReadBuildInfo(); ok && info != nil {
		for _, dep := range info.Deps {
			if dep != nil && dep.Path == AWGGoModulePath {
				recorded = dep.Version
				break
			}
		}
	}

	got := CompiledAWGGoVersion()
	t.Logf("build metadata records %s as %q; CompiledAWGGoVersion() = %q", AWGGoModulePath, recorded, got)

	if got == "" {
		t.Fatal("CompiledAWGGoVersion() returned an empty version")
	}
	if got != PinnedAWGGoVersion {
		t.Errorf(
			"compiled %s version is %q but PinnedAWGGoVersion is %q: the binary and the constant drifted",
			AWGGoModulePath,
			got,
			PinnedAWGGoVersion,
		)
	}
}

func TestAWGGoVersionFromModules(t *testing.T) {
	tests := []struct {
		name string
		deps []*debug.Module
		want string
	}{
		{
			name: "no build metadata",
			deps: nil,
			want: PinnedAWGGoVersion,
		},
		{
			name: "module not linked",
			deps: []*debug.Module{
				nil,
				{Path: "example.com/other", Version: "v1.0.0"},
			},
			want: PinnedAWGGoVersion,
		},
		{
			name: "compiled module version",
			deps: []*debug.Module{
				{Path: AWGGoModulePath, Version: "v3.1.20261201"},
			},
			want: "v3.1.20261201",
		},
		{
			name: "unversioned build",
			deps: []*debug.Module{
				{Path: AWGGoModulePath, Version: "(devel)"},
			},
			want: PinnedAWGGoVersion,
		},
		{
			name: "empty module version",
			deps: []*debug.Module{
				{Path: AWGGoModulePath, Version: ""},
			},
			want: PinnedAWGGoVersion,
		},
		{
			name: "versioned replacement",
			deps: []*debug.Module{
				{
					Path:    AWGGoModulePath,
					Version: "v3.1.20261116",
					Replace: &debug.Module{Path: "example.com/amneziawg-go-fork", Version: "v3.1.20260901"},
				},
			},
			want: "v3.1.20260901",
		},
		{
			name: "local directory replacement",
			deps: []*debug.Module{
				{
					Path:    AWGGoModulePath,
					Version: "v3.1.20261116",
					Replace: &debug.Module{Path: "../amneziawg-go"},
				},
			},
			want: PinnedAWGGoVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := awgGoVersionFromModules(tt.deps); got != tt.want {
				t.Errorf("awgGoVersionFromModules() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequiredVersion(t *testing.T) {
	tests := []struct {
		name   string
		goMod  string
		module string
		want   string
		wantOK bool
	}{
		{
			name:   "require block",
			goMod:  "module example.com/x\n\nrequire (\n\texample.com/dep v1.2.3\n)\n",
			module: "example.com/dep",
			want:   "v1.2.3",
			wantOK: true,
		},
		{
			name:   "single line require",
			goMod:  "module example.com/x\n\nrequire example.com/dep v1.2.3\n",
			module: "example.com/dep",
			want:   "v1.2.3",
			wantOK: true,
		},
		{
			name:   "indirect entry keeps its version",
			goMod:  "require (\n\texample.com/dep v1.2.3 // indirect\n)\n",
			module: "example.com/dep",
			want:   "v1.2.3",
			wantOK: true,
		},
		{
			name:   "replace directive is not a requirement",
			goMod:  "replace example.com/dep => example.com/fork v1.4.0\n",
			module: "example.com/dep",
			wantOK: false,
		},
		{
			name:   "missing module",
			goMod:  "require (\n\texample.com/other v1.2.3\n)\n",
			module: "example.com/dep",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := requiredVersion([]byte(tt.goMod), tt.module)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("requiredVersion() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// requiredVersion returns the version a go.mod file requires for modulePath.
// It reads only require directives, in block or single line form, so a replace
// directive is never mistaken for the required version.
func requiredVersion(goMod []byte, modulePath string) (string, bool) {
	inRequireBlock := false
	scanner := bufio.NewScanner(bytes.NewReader(goMod))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == modulePath {
				return fields[1], true
			}
			continue
		}

		switch {
		case line == "require (":
			inRequireBlock = true
		case strings.HasPrefix(line, "require "):
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 && fields[0] == modulePath {
				return fields[1], true
			}
		}
	}
	return "", false
}

// splitImage splits an image reference into its repository and tag.
func splitImage(image string) (repo, tag string, ok bool) {
	idx := strings.LastIndex(image, ":")
	if idx <= 0 || idx == len(image)-1 {
		return "", "", false
	}
	return image[:idx], image[idx+1:], true
}
