package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/devops-igor/amnezia-nexus/web"
)

// AppVersion represents the current version of the web panel.
const AppVersion = "2.1.0"

// AppCodename represents the release codename of the current version.
const AppCodename = "Pulsar"

// Paths represents the standard filesystem paths used by the application.
type Paths struct {
	DataDir   string
	DBPath    string
	SecretKey string
}

// Config / AppConfig contains runtime configuration parameters for the application.
type Config struct {
	AppVersion     string
	AppCodename    string
	Paths          *Paths
	Host           string
	Port           int
	DataDir        string
	DBPath         string
	SecretKey      string
	TrustedProxies []string
	TrustedCIDRs   []*net.IPNet
	TrustedIPs     []net.IP
	LogLevel       string
	CookieInsecure bool
	VPNEnabled     bool
	VPNListenPort  int
	VPNSubnet      string
}

// AppConfig is an alias for Config to match specification naming.
type AppConfig = Config

var (
	translationsMu sync.RWMutex
	translations   = make(map[string]map[string]string)
)

// ResolvePaths resolves the standard directory and file paths from DATA_DIR.
func ResolvePaths() *Paths {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	cleanDataDir := filepath.Clean(dataDir)

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = filepath.Join(cleanDataDir, "panel.db")
	} else {
		dbPath = filepath.Clean(dbPath)
	}

	return &Paths{
		DataDir:   cleanDataDir,
		DBPath:    dbPath,
		SecretKey: filepath.Join(cleanDataDir, ".secret_key"),
	}
}

var secretKeyMu sync.Mutex

// ResolveSecretKey resolves or generates the application SECRET_KEY per specification:
// 1. SECRET_KEY env variable
// 2. <DATA_DIR>/.secret_key file
// 3. Generate 32 crypto random bytes -> 64-char hex string, save atomically with 0600 permissions.
func ResolveSecretKey(dataDir string) (string, error) {
	if envKey := strings.TrimSpace(os.Getenv("SECRET_KEY")); envKey != "" {
		slog.Info("Using SECRET_KEY from environment variable")
		return envKey, nil
	}

	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()

	// Re-check environment variable under lock
	if envKey := strings.TrimSpace(os.Getenv("SECRET_KEY")); envKey != "" {
		slog.Info("Using SECRET_KEY from environment variable")
		return envKey, nil
	}

	cleanDataDir := filepath.Clean(dataDir)
	cleanKeyPath := filepath.Clean(filepath.Join(cleanDataDir, ".secret_key"))

	// #nosec G304 G703 -- Reading secret key from configured data directory is intended
	data, err := os.ReadFile(cleanKeyPath)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("secret key file %s is empty", cleanKeyPath)
		}
		slog.Info("Loaded SECRET_KEY from persistent storage")
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to read secret key file %s: %w", cleanKeyPath, err)
	}

	// Generate 32 bytes (64 hex characters)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	newKey := hex.EncodeToString(randomBytes)

	// Ensure directory exists
	// #nosec G703
	if err := os.MkdirAll(cleanDataDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create data dir %s: %w", cleanDataDir, err)
	}

	// Persist key atomically to temporary file with strict 0600 permissions, then move into place.
	// #nosec G304 G703
	tmpFile, err := os.CreateTemp(cleanDataDir, ".secret_key.tmp.*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary secret key file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		// #nosec G703
		_ = os.Remove(tmpPath)
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("failed to set permissions on secret key file: %w", err)
	}

	if _, err := tmpFile.WriteString(newKey + "\n"); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("failed to write secret key to temporary file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("failed to sync secret key file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close temporary secret key file: %w", err)
	}

	// Atomically place file into target destination.
	// We try os.Link first because it fails with os.ErrExist if another process
	// created the key concurrently, preventing silent overwrites.
	// #nosec G703
	if linkErr := os.Link(tmpPath, cleanKeyPath); linkErr == nil {
		// #nosec G703
		_ = os.Remove(tmpPath)
		slog.Warn("Generated new SECRET_KEY on first boot. Set SECRET_KEY in production to avoid persistence issues.")
		return newKey, nil
	} else if errors.Is(linkErr, os.ErrExist) {
		// Another process created the key concurrently; load and return it.
		// #nosec G304 G703
		persistedData, readErr := os.ReadFile(cleanKeyPath)
		if readErr != nil {
			return "", fmt.Errorf("failed to read concurrently created secret key file %s: %w", cleanKeyPath, readErr)
		}
		persistedKey := strings.TrimSpace(string(persistedData))
		if persistedKey == "" {
			return "", fmt.Errorf("concurrently created secret key file %s is empty", cleanKeyPath)
		}
		slog.Info("Loaded SECRET_KEY from persistent storage")
		return persistedKey, nil
	} else {
		// If link is not supported across filesystem boundaries or platform, fall back to atomic rename.
		// #nosec G304 G703
		if renameErr := os.Rename(tmpPath, cleanKeyPath); renameErr != nil {
			return "", fmt.Errorf("failed to persist secret key to %s: %w", cleanKeyPath, renameErr)
		}
		slog.Warn("Generated new SECRET_KEY on first boot. Set SECRET_KEY in production to avoid persistence issues.")
		return newKey, nil
	}
}

// Load initializes configuration from environment variables and local secrets.
func Load() (*Config, error) {
	return LoadConfig()
}

// LoadConfig initializes AppConfig per specification.
func LoadConfig() (*AppConfig, error) {
	paths := ResolvePaths()

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port := 5000
	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = os.Getenv("PANEL_PORT")
	}
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}

	trustedProxies, trustedCIDRs, trustedIPs := parseTrustedProxies(strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")))

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	// Dev-only opt-in to disable the Secure flag on session cookies. Any of
	// "1", "true", "TRUE", ... counts; only TLS-bearing production deployments
	// should ever leave this unset.
	cookieInsecure := false
	if raw := strings.TrimSpace(os.Getenv("COOKIE_INSECURE")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil && parsed {
			cookieInsecure = true
		}
	}

	vpnEnabled := strings.EqualFold(os.Getenv("VPN_ENABLED"), "true") || os.Getenv("VPN_ENABLED") == "1"

	vpnListenPort := 51820
	if vpnPortStr := os.Getenv("VPN_LISTEN_PORT"); vpnPortStr != "" {
		if p, err := strconv.Atoi(vpnPortStr); err == nil && p > 0 && p <= 65535 {
			vpnListenPort = p
		}
	}

	vpnSubnet := os.Getenv("VPN_SUBNET")
	if vpnSubnet == "" {
		vpnSubnet = "10.100.0.0/16"
	}

	secretKey, err := ResolveSecretKey(paths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve secret key: %w", err)
	}

	return &Config{
		AppVersion:     AppVersion,
		AppCodename:    AppCodename,
		Paths:          paths,
		Host:           host,
		Port:           port,
		DataDir:        paths.DataDir,
		DBPath:         paths.DBPath,
		SecretKey:      secretKey,
		TrustedProxies: trustedProxies,
		TrustedCIDRs:   trustedCIDRs,
		TrustedIPs:     trustedIPs,
		LogLevel:       logLevel,
		CookieInsecure: cookieInsecure,
		VPNEnabled:     vpnEnabled,
		VPNListenPort:  vpnListenPort,
		VPNSubnet:      vpnSubnet,
	}, nil
}

func parseTrustedProxies(rawProxies string) ([]string, []*net.IPNet, []net.IP) {
	if rawProxies == "" {
		return nil, nil, nil
	}
	var trustedProxies []string
	var trustedCIDRs []*net.IPNet
	var trustedIPs []net.IP
	for _, proxy := range strings.Split(rawProxies, ",") {
		trimmed := strings.TrimSpace(proxy)
		if trimmed == "" {
			continue
		}
		trustedProxies = append(trustedProxies, trimmed)
		if strings.Contains(trimmed, "/") {
			if _, ipNet, err := net.ParseCIDR(trimmed); err == nil {
				trustedCIDRs = append(trustedCIDRs, ipNet)
			}
		} else {
			if ip := net.ParseIP(trimmed); ip != nil {
				trustedIPs = append(trustedIPs, ip)
			}
		}
	}
	return trustedProxies, trustedCIDRs, trustedIPs
}

// LoadTranslations loads and caches all translation dictionaries from the embedded web FS.
func LoadTranslations() error {
	translationsMu.Lock()
	defer translationsMu.Unlock()

	subFS, err := web.GetTranslationsSubFS()
	if err != nil {
		return fmt.Errorf("failed to open embedded translations FS: %w", err)
	}

	entries, err := fs.ReadDir(subFS, ".")
	if err != nil {
		return fmt.Errorf("failed to read translations dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			lang := strings.TrimSuffix(entry.Name(), ".json")
			data, err := fs.ReadFile(subFS, entry.Name())
			if err != nil {
				return fmt.Errorf("failed to read translation file %s: %w", entry.Name(), err)
			}

			var dict map[string]string
			if err := json.Unmarshal(data, &dict); err != nil {
				return fmt.Errorf("failed to parse translation json %s: %w", entry.Name(), err)
			}

			translations[lang] = dict
		}
	}

	return nil
}

// T translates a key for the given language with fallback to English, then raw key.
func T(lang, key string) string {
	translationsMu.RLock()
	defer translationsMu.RUnlock()

	if dict, ok := translations[lang]; ok {
		if val, exists := dict[key]; exists && val != "" {
			return val
		}
	}

	// Fallback to English
	if dict, ok := translations["en"]; ok {
		if val, exists := dict[key]; exists && val != "" {
			return val
		}
	}

	return key
}

// Translate is an alias for T.
func Translate(lang, key string) string {
	return T(lang, key)
}

// GetTranslations returns a copy of all loaded translations.
func GetTranslations() map[string]map[string]string {
	translationsMu.RLock()
	defer translationsMu.RUnlock()

	res := make(map[string]map[string]string, len(translations))
	for lang, dict := range translations {
		dictCopy := make(map[string]string, len(dict))
		for k, v := range dict {
			dictCopy[k] = v
		}
		res[lang] = dictCopy
	}
	return res
}

// IsValidLanguage checks if the language code is supported.
func IsValidLanguage(lang string) bool {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "en", "ru", "fr", "zh", "fa":
		return true
	default:
		return false
	}
}
