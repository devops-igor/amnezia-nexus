package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

// Resolve identity before dialing. A failed store lookup must never become a
// first-contact decision; provider identity is authoritative over address reuse.
func (h *Handlers) resolveDeployServerID(ctx context.Context, assignedIP string, req GigahostDeployRequest) (*int64, error) {
	if h.db == nil {
		return nil, errors.New("database not available")
	}
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve SSH server identity: %w", err)
	}
	var hostID *int64
	for _, s := range servers {
		if req.ProviderServerID > 0 && s.Protocols["provider"] == "gigahost" && matchProviderServerID(s.Protocols["provider_server_id"], req.ProviderServerID) {
			id := s.ID
			return &id, nil
		}
		if strings.EqualFold(strings.TrimSpace(s.Host), strings.TrimSpace(assignedIP)) {
			id := s.ID
			hostID = &id
		}
	}
	if req.OrderID != "" {
		_, id, _, _, err := h.getDeployOrderByID(ctx, req.OrderID)
		if err != nil {
			return nil, fmt.Errorf("resolve SSH order identity: %w", err)
		}
		if id > 0 {
			return &id, nil
		}
	}
	return hostID, nil
}

func validateSSHKeyInvariants(key gossh.PublicKey) error {
	if key == nil {
		return errors.New("nil SSH host key")
	}
	parsed, err := gossh.ParsePublicKey(key.Marshal())
	if err != nil || parsed.Type() != key.Type() || !bytes.Equal(parsed.Marshal(), key.Marshal()) {
		return errors.New("malformed SSH host key")
	}
	switch parsed.Type() {
	case gossh.KeyAlgoED25519, gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521:
		return nil
	case gossh.KeyAlgoRSA:
		pub, ok := parsed.(gossh.CryptoPublicKey)
		if ok {
			if rsaKey, ok := pub.CryptoPublicKey().(*rsa.PublicKey); ok && rsaKey.N.BitLen() >= 2048 {
				return nil
			}
		}
	}
	return fmt.Errorf("unsupported or weak SSH host key: %s", parsed.Type())
}

func deployExpectedFingerprint(req GigahostDeployRequest) string {
	if req.ExpectedFingerprint != "" {
		return strings.TrimSpace(req.ExpectedFingerprint)
	}
	return strings.TrimSpace(req.HostKeyFingerprint)
}

func (h *Handlers) buildDeployHostKeyCallback(ctx context.Context, req GigahostDeployRequest, serverID *int64, capturedFPOut *string) gossh.HostKeyCallback {
	expected := deployExpectedFingerprint(req)
	return func(hostname string, _ net.Addr, key gossh.PublicKey) error {
		if err := validateSSHKeyInvariants(key); err != nil {
			return err
		}
		actual := ssh.FingerprintSHA256(key)
		if expected != "" {
			if err := validateFingerprintFormat(expected); err != nil {
				return err
			}
			if expected != actual {
				return fmt.Errorf("host key fingerprint mismatch: expected %s, got %s", expected, actual)
			}
		}
		known := ""
		if serverID != nil {
			if h.db == nil {
				return errors.New("host identity store unavailable")
			}
			var err error
			known, err = h.db.GetKnownHostFingerprint(ctx, *serverID)
			if err != nil {
				return fmt.Errorf("query known SSH identity: %w", err)
			}
			if known != "" && known != actual {
				return &ssh.ErrHostKeyMismatch{ServerID: *serverID, Host: hostname, Expected: known, Actual: actual}
			}
		}
		if known == "" && expected == "" {
			// A boolean alone does not identify what the administrator confirmed.
			return &ssh.ErrFingerprintRequired{Host: hostname, Fingerprint: actual}
		}
		if serverID != nil {
			if err := h.db.BindKnownHostFingerprint(ctx, *serverID, actual); err != nil {
				return err
			}
		}
		if capturedFPOut != nil {
			*capturedFPOut = actual
		}
		return nil
	}
}

func (h *Handlers) verifyDeploySSHAccess(ctx context.Context, assignedIP string, req GigahostDeployRequest) (string, error) {
	sshPort := req.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}
	user := strings.TrimSpace(req.SSHUser)
	if user == "" {
		user = "root"
	}
	serverID, err := h.resolveDeployServerID(ctx, assignedIP, req)
	if err != nil {
		return "", err
	}
	var captured string
	cfg := ssh.Config{Host: assignedIP, Port: sshPort, User: user, Password: req.SSHPassword, PrivateKey: req.SSHPrivateKey, Timeout: 15 * time.Second, Store: h.db, ServerID: serverID, RequireFingerprintConfirm: true,
		HostKeyCallback: h.buildDeployHostKeyCallback(ctx, req, serverID, &captured)}
	client, err := h.dialDeploySSH(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if fc, ok := client.(interface{ CapturedFingerprint() string }); ok && captured == "" {
		captured = fc.CapturedFingerprint()
	}
	if err := validateFingerprintFormat(captured); err != nil {
		return "", fmt.Errorf("invalid verified host identity: %w", err)
	}
	if expected := deployExpectedFingerprint(req); expected != "" && expected != captured {
		return "", errors.New("verified SSH identity does not match expected fingerprint")
	}
	return captured, nil
}

func validateFingerprintFormat(fp string) error {
	return models.ValidateHostFingerprint(fp)
}
