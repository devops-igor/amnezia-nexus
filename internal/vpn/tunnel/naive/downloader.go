package naive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	// DefaultReleaseTag is the pinned upstream NaiveProxy release tag.
	DefaultReleaseTag = "v154.0.8037.49-5"

	// DefaultNaiveBinPath is the default persistent storage path for the naive binary.
	DefaultNaiveBinPath = "/var/lib/amnezia-nexus/bin/naive"

	// NaiveBinPathEnv is the environment variable to override the binary storage path.
	NaiveBinPathEnv = "NAIVE_BIN_PATH"

	// NaiveDownloadBaseURLEnv is the environment variable to override the base download URL.
	NaiveDownloadBaseURLEnv = "NAIVE_DOWNLOAD_BASE_URL"

	defaultBaseURL = "https://github.com/klzgrad/naiveproxy/releases/download"
)

// pinnedChecksums stores verified SHA-256 checksums and asset naming conventions.
var pinnedChecksums = map[string]map[string]struct {
	assetSuffix string
	sha256Hex   string
}{
	DefaultReleaseTag: {
		"amd64": {
			assetSuffix: "-openwrt-x86_64.tar.xz",
			sha256Hex:   "1eaf0fdbc1ae5d253502b6095221d6a745ac23241faa83c9afb0a1ad76b9ddfa",
		},
		"arm64": {
			assetSuffix: "-openwrt-aarch64_generic.tar.xz",
			sha256Hex:   "c9930d6e2733817ff773fe10b21c1a890d92a548a3301dfb51ccd3b4234fe938",
		},
	},
}

var downloadMu sync.Mutex

// GetNaiveBinPath returns the configured path to the naive binary.
func GetNaiveBinPath() string {
	if p := os.Getenv(NaiveBinPathEnv); p != "" {
		return filepath.Clean(p)
	}
	if fi, err := os.Stat("/app/data"); err == nil && fi.IsDir() {
		return "/app/data/bin/naive"
	}
	if fi, err := os.Stat("./data"); err == nil && fi.IsDir() {
		return "./data/bin/naive"
	}
	return DefaultNaiveBinPath
}

// GetReleaseAsset resolves the archive asset name and expected SHA-256 for the given tag and architecture.
func GetReleaseAsset(tag, arch string) (assetName, sha256Hex string, err error) {
	if tag == "" {
		tag = DefaultReleaseTag
	}
	tagAssets, ok := pinnedChecksums[tag]
	if !ok {
		return "", "", fmt.Errorf("naive: unsupported release tag %q (no pinned checksums)", tag)
	}

	info, ok := tagAssets[arch]
	if !ok {
		return "", "", fmt.Errorf("naive: unsupported host architecture %q for upstream binary", arch)
	}

	assetName = "naiveproxy-" + tag + info.assetSuffix
	return assetName, info.sha256Hex, nil
}

// ResolveDownloadURL builds the full download URL and returns the expected SHA-256 checksum.
func ResolveDownloadURL(baseURL, tag, arch string) (downloadURL, sha256Hex string, err error) {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if tag == "" {
		tag = DefaultReleaseTag
	}

	assetName, expectedSHA, err := GetReleaseAsset(tag, arch)
	if err != nil {
		return "", "", err
	}

	downloadURL = fmt.Sprintf("%s/%s/%s", strings.TrimRight(baseURL, "/"), tag, assetName)
	return downloadURL, expectedSHA, nil
}

// IsBinaryAvailable reports whether an executable naive binary exists on the configured path.
func IsBinaryAvailable() bool {
	return isExecutable(GetNaiveBinPath())
}

// isExecutable checks whether the file at path exists, is a regular file, and has executable bits set.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

// EnsureNaiveBinary checks if the naive binary exists in persistent storage.
// If missing, it downloads, validates SHA-256, extracts, and installs the binary.
// Subsequent calls reuse the cached binary without network calls.
func EnsureNaiveBinary(ctx context.Context) (string, error) {
	binPath := GetNaiveBinPath()
	if isExecutable(binPath) {
		return binPath, nil
	}

	downloadMu.Lock()
	defer downloadMu.Unlock()

	// Re-check under lock in case another goroutine just completed the download.
	if isExecutable(binPath) {
		return binPath, nil
	}

	baseURL := os.Getenv(NaiveDownloadBaseURLEnv)
	if err := DownloadNaiveBinary(ctx, binPath, baseURL, DefaultReleaseTag); err != nil {
		return "", err
	}

	return binPath, nil
}

// DownloadNaiveBinary resolves the release asset for runtime.GOARCH, downloads the archive,
// verifies the SHA-256 checksum, extracts the binary, and installs it to destPath with mode 0755.
func DownloadNaiveBinary(ctx context.Context, destPath, baseURL, tag string) error {
	downloadURL, expectedSHA, err := ResolveDownloadURL(baseURL, tag, runtime.GOARCH)
	if err != nil {
		return err
	}
	return DownloadNaiveBinaryWithExpectedSHA(ctx, destPath, downloadURL, expectedSHA)
}

// DownloadNaiveBinaryWithExpectedSHA downloads the archive from downloadURL, verifies expectedSHA,
// extracts the naive executable, and installs it into destPath with mode 0755.
func DownloadNaiveBinaryWithExpectedSHA(ctx context.Context, destPath, downloadURL, expectedSHA string) error {
	if destPath == "" {
		return errors.New("naive: empty destination binary path")
	}

	destDir := filepath.Dir(destPath)
	// #nosec G301 -- destination directory requires 0755 permissions for unprivileged execution
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("naive: failed to create destination directory %s: %w", destDir, err)
	}

	tmpDir, err := os.MkdirTemp("", "naive-dl-*")
	if err != nil {
		return fmt.Errorf("naive: failed to create temporary download directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	archivePath := filepath.Clean(filepath.Join(tmpDir, "archive.tar.xz"))
	// #nosec G304 -- archivePath is located inside a temporary directory created by os.MkdirTemp
	archiveFile, err := os.OpenFile(archivePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("naive: failed to create temporary archive file: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		_ = archiveFile.Close()
		return fmt.Errorf("naive: invalid download request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_ = archiveFile.Close()
		return fmt.Errorf("naive: download request failed for %s: %w", downloadURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		_ = archiveFile.Close()
		return fmt.Errorf("naive: download failed with HTTP status %d for %s", resp.StatusCode, downloadURL)
	}

	hasher := sha256.New()
	tee := io.TeeReader(resp.Body, hasher)

	if _, err := io.Copy(archiveFile, tee); err != nil {
		_ = archiveFile.Close()
		return fmt.Errorf("naive: failed to write download body: %w", err)
	}
	if err := archiveFile.Close(); err != nil {
		return fmt.Errorf("naive: failed to close download archive: %w", err)
	}

	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && !strings.EqualFold(computedSHA, expectedSHA) {
		return fmt.Errorf("naive: checksum mismatch for %s: got %s, want %s", downloadURL, computedSHA, expectedSHA)
	}

	extractDir := filepath.Join(tmpDir, "extracted")
	// #nosec G301 -- extraction directory requires 0755 permissions for unprivileged execution
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("naive: failed to create extraction directory: %w", err)
	}

	// #nosec G204 -- archivePath and extractDir are validated internal temporary paths
	tarCmd := exec.CommandContext(ctx, "tar", "-xf", archivePath, "-C", extractDir)
	if out, err := tarCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("naive: tar extraction failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	var foundBinary string
	walkErr := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "naive" {
			foundBinary = path
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("naive: failed to search extracted archive: %w", walkErr)
	}
	if foundBinary == "" {
		return errors.New("naive: executable 'naive' not found in downloaded archive")
	}

	tmpDest, err := os.CreateTemp(destDir, "naive-install-*")
	if err != nil {
		return fmt.Errorf("naive: failed to create temporary install file in %s: %w", destDir, err)
	}
	tmpDestPath := tmpDest.Name()
	defer func() {
		_ = os.Remove(tmpDestPath)
	}()

	// #nosec G304 -- foundBinary is located inside the temporary extraction directory
	srcFile, err := os.Open(filepath.Clean(foundBinary))
	if err != nil {
		_ = tmpDest.Close()
		return fmt.Errorf("naive: failed to open extracted binary: %w", err)
	}
	if _, err := io.Copy(tmpDest, srcFile); err != nil {
		_ = srcFile.Close()
		_ = tmpDest.Close()
		return fmt.Errorf("naive: failed to copy binary to destination: %w", err)
	}
	_ = srcFile.Close()

	if err := tmpDest.Chmod(0755); err != nil {
		_ = tmpDest.Close()
		return fmt.Errorf("naive: failed to chmod binary: %w", err)
	}
	if err := tmpDest.Close(); err != nil {
		return fmt.Errorf("naive: failed to close installed binary: %w", err)
	}

	if err := os.Rename(tmpDestPath, destPath); err != nil {
		return fmt.Errorf("naive: failed to atomically move binary to %s: %w", destPath, err)
	}

	return nil
}
