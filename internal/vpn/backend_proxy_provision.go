package vpn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

// ResolveServerProxyProtocol inspects server.Protocols. If AWG is not installed,
// it checks whether VLESS or Naive is installed and returns the protocol name and its
// derived or preserved protocol parameters.
func ResolveServerProxyProtocol(server *models.Server) (string, json.RawMessage, error) {
	if server == nil || server.Protocols == nil {
		return "", nil, nil
	}
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
		if inst, _ := awgInfo["installed"].(bool); inst {
			return "", nil, nil
		}
		if pub, _ := awgInfo["public_key"].(string); pub != "" {
			return "", nil, nil
		}
	}
	for _, p := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		if pInfo, ok := server.Protocols[p].(map[string]any); ok {
			if inst, _ := pInfo["installed"].(bool); inst {
				params, err := DeriveProxyProtocolParams(server, p)
				if err != nil {
					return "", nil, err
				}
				return p, params, nil
			}
		}
	}
	return "", nil, nil
}

// DeriveProxyProtocolParams constructs typed protocol parameters (VLESSRealityParams
// or NaiveProxyParams) for a server that has the proxy protocol installed in server.Protocols.
// If valid params or protocol_params are already present, they are preserved.
// Otherwise, dedicated internal backend client credentials and connection parameters
// are securely auto-provisioned.
func DeriveProxyProtocolParams(server *models.Server, proto string) (json.RawMessage, error) {
	if server == nil || server.Protocols == nil {
		return nil, errors.New("server protocols not available")
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	pInfo, ok := server.Protocols[normProto].(map[string]any)
	if !ok || pInfo == nil {
		return nil, fmt.Errorf("protocol %s not configured on server", normProto)
	}

	// 1. Preserve existing params or protocol_params if already populated in metadata.
	if pVal, ok := pInfo["params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			return b, nil
		}
	}
	if pVal, ok := pInfo["protocol_params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			return b, nil
		}
	}

	// 2. Auto-provision dedicated internal backend client credentials based on protocol.
	switch normProto {
	case models.ProtocolVLESS:
		return deriveVLESSParams(server, pInfo)
	case models.ProtocolNaive:
		return deriveNaiveParams(server, pInfo)
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", normProto)
	}
}

func deriveVLESSParams(server *models.Server, pInfo map[string]any) (json.RawMessage, error) {
	flow := "xtls-rprx-vision"
	if f, ok := pInfo["flow"].(string); ok && strings.TrimSpace(f) != "" {
		flow = strings.TrimSpace(f)
	}
	if flow == "none" {
		flow = ""
	}

	serverName := "gateway.icloud.com"
	if sn, ok := pInfo["server_name"].(string); ok && strings.TrimSpace(sn) != "" {
		serverName = strings.TrimSpace(sn)
	} else if server.Host != "" && net.ParseIP(server.Host) == nil {
		serverName = server.Host
	}

	pubKey := ""
	if pk, ok := pInfo["public_key"].(string); ok && strings.TrimSpace(pk) != "" {
		pubKey = strings.TrimSpace(pk)
	} else {
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate reality keypair: %w", err)
		}
		pubKey = base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	}

	shortID := ""
	if sid, ok := pInfo["short_id"].(string); ok && strings.TrimSpace(sid) != "" {
		shortID = strings.TrimSpace(sid)
	} else {
		sidBytes := make([]byte, 8)
		if _, err := rand.Read(sidBytes); err != nil {
			return nil, fmt.Errorf("failed to generate short id: %w", err)
		}
		shortID = hex.EncodeToString(sidBytes)
	}

	vlessParams := models.VLESSRealityParams{
		UUID:        uuid.NewString(),
		Flow:        flow,
		PublicKey:   pubKey,
		ShortID:     shortID,
		ServerName:  serverName,
		Fingerprint: "chrome",
		Transport:   "tcp",
	}
	return json.Marshal(vlessParams)
}

func deriveNaiveParams(server *models.Server, pInfo map[string]any) (json.RawMessage, error) {
	domain := strings.TrimSpace(server.Host)
	if d, ok := pInfo["domain"].(string); ok && strings.TrimSpace(d) != "" {
		domain = strings.TrimSpace(d)
	}
	if h, _, err := net.SplitHostPort(domain); err == nil && h != "" {
		domain = h
	}
	if domain == "" {
		domain = "localhost"
	}

	uBytes := make([]byte, 6)
	if _, err := rand.Read(uBytes); err != nil {
		return nil, fmt.Errorf("failed to generate naive username: %w", err)
	}
	pBytes := make([]byte, 16)
	if _, err := rand.Read(pBytes); err != nil {
		return nil, fmt.Errorf("failed to generate naive password: %w", err)
	}

	naiveParams := models.NaiveProxyParams{
		Username: fmt.Sprintf("user_%s", hex.EncodeToString(uBytes)),
		Password: hex.EncodeToString(pBytes),
		Domain:   domain,
		EnableH3: false,
	}
	// #nosec G117 -- Dedicated internal backend credentials marshaled for encrypted persistence
	return json.Marshal(naiveParams)
}
