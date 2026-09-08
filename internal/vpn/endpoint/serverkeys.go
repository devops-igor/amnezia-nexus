package endpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/security"
	"golang.org/x/crypto/curve25519"
)

// ServerKeysManager provides the endpoint's persistent Noise/WireGuard server keypair.
// The private key survives restarts so already-issued client configs stay valid:
// it is stored (base64, Fernet-encrypted with the DB secret key) in the vpn_config
// setting under VPNConfig.ServerPrivateKey, the same encryption pattern as backend
// tunnel keys (database.CreateBackendTunnel / security.EncryptCredential).
type ServerKeysManager struct {
	mu     sync.Mutex
	db     *database.DB
	priv   [32]byte
	pub    [32]byte
	loaded bool
}

// NewServerKeysManager creates a keys manager bound to the settings store.
func NewServerKeysManager(db *database.DB) *ServerKeysManager {
	return &ServerKeysManager{db: db}
}

// EnsureKeypair returns the persistent server keypair, generating and persisting
// one on first use. When db is nil it falls back to an ephemeral in-memory
// keypair (tests / no-database deployments) — callers that need stability
// across restarts must pass a database.
func (m *ServerKeysManager) EnsureKeypair(ctx context.Context) (priv, pub [32]byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return m.priv, m.pub, nil
	}

	if m.db != nil {
		priv, pub, err = m.loadOrCreate(ctx)
	} else {
		priv, pub, err = generateKeyPair()
	}
	if err != nil {
		return priv, pub, err
	}

	m.priv, m.pub, m.loaded = priv, pub, true
	return priv, pub, nil
}

// PublicKey returns the cached public key (zero value if not loaded yet).
func (m *ServerKeysManager) PublicKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return base64.StdEncoding.EncodeToString(m.pub[:])
}

// PrivateKeyB64 returns the cached private key base64-encoded (zero value if not loaded yet).
func (m *ServerKeysManager) PrivateKeyB64() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return base64.StdEncoding.EncodeToString(m.priv[:])
}

func (m *ServerKeysManager) loadOrCreate(ctx context.Context) (priv, pub [32]byte, err error) {
	cfg, err := m.db.GetVPNConfig(ctx)
	if err != nil {
		return priv, pub, fmt.Errorf("failed to load vpn config for server keypair: %w", err)
	}

	// Existing key: decrypt and verify.
	if cfg.ServerPrivateKey != "" {
		privB64, decErr := security.DecryptCredential(cfg.ServerPrivateKey, m.db.SecretKey())
		if decErr == nil && privB64 != "" {
			raw, decErr2 := base64.StdEncoding.DecodeString(privB64)
			if decErr2 == nil && len(raw) == 32 {
				copy(priv[:], raw)
				pubRaw, dhErr := curve25519.X25519(priv[:], curve25519.Basepoint)
				if dhErr == nil {
					copy(pub[:], pubRaw)
					return priv, pub, nil
				}
			}
		}
		// Corrupt/undecryptable key: fall through and regenerate below.
	}

	// Generate a new keypair and persist it (Fernet-encrypted).
	priv, pub, err = generateKeyPair()
	if err != nil {
		return priv, pub, err
	}

	privB64 := base64.StdEncoding.EncodeToString(priv[:])
	enc, err := security.EncryptCredential(privB64, m.db.SecretKey())
	if err != nil {
		return priv, pub, fmt.Errorf("failed to encrypt server private key: %w", err)
	}

	cfg.ServerPrivateKey = enc
	cfg.ServerPublicKey = base64.StdEncoding.EncodeToString(pub[:])
	if err := m.db.SaveVPNConfig(ctx, cfg); err != nil {
		return priv, pub, fmt.Errorf("failed to persist server keypair: %w", err)
	}
	return priv, pub, nil
}

// generateKeyPair generates a fresh Curve25519 keypair.
func generateKeyPair() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, fmt.Errorf("failed to generate server private key: %w", err)
	}
	pubAny, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("failed to derive server public key: %w", err)
	}
	copy(pub[:], pubAny)
	return priv, pub, nil
}

// GetServerPublicKey is a convenience helper: returns the persistent public key,
// generating it if needed.
func (m *ServerKeysManager) GetServerPublicKey(ctx context.Context) (string, error) {
	if _, pub, err := m.EnsureKeypair(ctx); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(pub[:]), nil
	}
}
