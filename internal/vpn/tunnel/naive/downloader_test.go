package naive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestArchitectureMapping(t *testing.T) {
	tests := []struct {
		name       string
		arch       string
		wantSuffix string
		wantSHA    string
		wantErr    bool
	}{
		{
			name:       "amd64",
			arch:       "amd64",
			wantSuffix: "-openwrt-x86_64.tar.xz",
			wantSHA:    "1eaf0fdbc1ae5d253502b6095221d6a745ac23241faa83c9afb0a1ad76b9ddfa",
			wantErr:    false,
		},
		{
			name:       "arm64",
			arch:       "arm64",
			wantSuffix: "-openwrt-aarch64_generic.tar.xz",
			wantSHA:    "c9930d6e2733817ff773fe10b21c1a890d92a548a3301dfb51ccd3b4234fe938",
			wantErr:    false,
		},
		{
			name:    "unsupported arch",
			arch:    "mipsle",
			wantErr: true,
		},
		{
			name:    "unsupported arch s390x",
			arch:    "s390x",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assetName, sha, err := GetReleaseAsset(DefaultReleaseTag, tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for arch %q, got nil", tt.arch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for arch %q: %v", tt.arch, err)
			}
			if !strings.HasSuffix(assetName, tt.wantSuffix) {
				t.Errorf("assetName %q does not end with %q", assetName, tt.wantSuffix)
			}
			if sha != tt.wantSHA {
				t.Errorf("expected SHA %q, got %q", tt.wantSHA, sha)
			}
		})
	}
}

func TestResolveDownloadURL(t *testing.T) {
	u, sha, err := ResolveDownloadURL("", "", "amd64")
	if err != nil {
		t.Fatalf("ResolveDownloadURL: %v", err)
	}
	expected := "https://github.com/klzgrad/naiveproxy/releases/download/v154.0.8037.49-5/naiveproxy-v154.0.8037.49-5-openwrt-x86_64.tar.xz"
	if u != expected {
		t.Errorf("got URL %q, want %q", u, expected)
	}
	if sha != "1eaf0fdbc1ae5d253502b6095221d6a745ac23241faa83c9afb0a1ad76b9ddfa" {
		t.Errorf("unexpected sha: %s", sha)
	}

	customBase := "http://127.0.0.1:9000/custom"
	uCustom, _, err := ResolveDownloadURL(customBase, "v154.0.8037.49-5", "arm64")
	if err != nil {
		t.Fatalf("ResolveDownloadURL custom: %v", err)
	}
	if !strings.HasPrefix(uCustom, customBase) {
		t.Errorf("expected prefix %q, got %q", customBase, uCustom)
	}
}

// buildMockTarXz creates a .tar.xz archive containing a dummy binary with the given name.
func buildMockTarXz(t *testing.T, binName string) []byte {
	t.Helper()
	tempDir := t.TempDir()

	srcPath := filepath.Join(tempDir, binName)
	if err := os.WriteFile(srcPath, []byte("#!/bin/sh\necho mock naive\n"), 0755); err != nil {
		t.Fatalf("write mock binary: %v", err)
	}

	archivePath := filepath.Join(tempDir, "archive.tar.xz")
	cmd := exec.Command("tar", "-cJf", archivePath, "-C", tempDir, binName)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar -cJf failed: %v (output: %s)", err, string(out))
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	return data
}

func TestDownloadNaiveBinary_MockServer(t *testing.T) {
	mockArchive := buildMockTarXz(t, "naive")
	h := sha256.Sum256(mockArchive)
	validSHA := hex.EncodeToString(h[:])

	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/x-xz")
		_, _ = w.Write(mockArchive)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targetDir := t.TempDir()
	targetBin := filepath.Join(targetDir, "bin", "naive")

	// 1. Success case: matching checksum
	err := DownloadNaiveBinaryWithExpectedSHA(ctx, targetBin, ts.URL+"/naive.tar.xz", validSHA)
	if err != nil {
		t.Fatalf("DownloadNaiveBinaryWithExpectedSHA failed: %v", err)
	}

	info, err := os.Stat(targetBin)
	if err != nil {
		t.Fatalf("target binary not found: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected file mode 0755, got %v", info.Mode().Perm())
	}

	// 2. Failure case: checksum mismatch
	targetBinFail := filepath.Join(targetDir, "bin2", "naive")
	badSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	err = DownloadNaiveBinaryWithExpectedSHA(ctx, targetBinFail, ts.URL+"/naive.tar.xz", badSHA)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch in error, got %v", err)
	}
	if _, err := os.Stat(targetBinFail); !os.IsNotExist(err) {
		t.Errorf("expected targetBinFail to not exist, got err: %v", err)
	}

	// 3. Failure case: missing naive binary inside archive
	emptyArchive := buildMockTarXz(t, "not-naive")
	emptyH := sha256.Sum256(emptyArchive)
	emptySHA := hex.EncodeToString(emptyH[:])

	tsEmpty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(emptyArchive)
	}))
	defer tsEmpty.Close()

	targetBinMissing := filepath.Join(targetDir, "bin3", "naive")
	err = DownloadNaiveBinaryWithExpectedSHA(ctx, targetBinMissing, tsEmpty.URL+"/archive.tar.xz", emptySHA)
	if err == nil {
		t.Fatal("expected error for missing naive binary in archive, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestEnsureNaiveBinary_IdempotentCache(t *testing.T) {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "naive")

	// Pre-create executable binary
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write pre-existing binary: %v", err)
	}

	t.Setenv(NaiveBinPathEnv, binPath)
	// Point base URL to an invalid address to prove NO network calls occur
	t.Setenv(NaiveDownloadBaseURLEnv, "http://127.0.0.1:0/unreachable")

	ctx := context.Background()
	gotPath, err := EnsureNaiveBinary(ctx)
	if err != nil {
		t.Fatalf("EnsureNaiveBinary failed: %v", err)
	}
	if gotPath != binPath {
		t.Errorf("got path %q, want %q", gotPath, binPath)
	}
}

// Ensure tar import is kept for tests
var _ = tar.Header{}
var _ = bytes.Buffer{}
