package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// XrayConfig models the top-level xray config.json structure.
//
//nolint:revive
type XrayConfig struct {
	Log       XrayLog        `json:"log"`
	DNS       *XrayDNS       `json:"dns,omitempty"`
	Inbounds  []XrayInbound  `json:"inbounds"`
	Outbounds []XrayOutbound `json:"outbounds"`
}

//nolint:revive
type XrayLog struct {
	LogLevel string `json:"loglevel"`
}

//nolint:revive
type XrayDNS struct {
	Servers       []string `json:"servers"`
	QueryStrategy string   `json:"queryStrategy"`
}

//nolint:revive
type XrayInbound struct {
	Port           int                 `json:"port"`
	Protocol       string              `json:"protocol"`
	Settings       XrayInboundSettings `json:"settings"`
	StreamSettings XrayStreamSettings  `json:"streamSettings"`
}

//nolint:revive
type XrayInboundSettings struct {
	Clients    []XrayClient `json:"clients"`
	Decryption string       `json:"decryption"`
}

//nolint:revive
type XrayClient struct {
	ID    string `json:"id"`
	Flow  string `json:"flow,omitempty"`
	Email string `json:"email,omitempty"`
}

//nolint:revive
type XrayStreamSettings struct {
	Network         string              `json:"network"`
	Security        string              `json:"security"`
	RealitySettings XrayRealitySettings `json:"realitySettings"`
}

//nolint:revive
type XrayRealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

//nolint:revive
type XrayOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

// GenerateRealityKeypair produces an x25519 keypair encoded as unpadded URL-safe base64.
func GenerateRealityKeypair() (privB64, pubB64 string, err error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}
	privB64 = base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	pubB64 = base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	return privB64, pubB64, nil
}

// DerivePublicKey derives the base64-RawURL public key corresponding to an x25519 private key.
func DerivePublicKey(privB64 string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(privB64)
		if err != nil {
			return "", fmt.Errorf("decode reality private key: %w", err)
		}
	}
	privKey, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", fmt.Errorf("parse x25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes()), nil
}

// GenerateShortID produces an 8-byte hexadecimal string.
func GenerateShortID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateShortIDPool provisions a pool of 4 to 8 distinct random 8-byte hexadecimal short IDs,
// plus an optional empty short ID ("") for REALITY clients that do not specify a short ID.
func GenerateShortIDPool(count int) ([]string, error) {
	if count < 4 {
		count = 4
	}
	if count > 8 {
		count = 8
	}

	seen := make(map[string]bool)
	pool := make([]string, 0, count+1)
	for len(pool) < count {
		sid, err := GenerateShortID()
		if err != nil {
			return nil, fmt.Errorf("generate short id: %w", err)
		}
		if !seen[sid] {
			seen[sid] = true
			pool = append(pool, sid)
		}
	}
	pool = append(pool, "")
	return pool, nil
}

// RenderXrayConfig generates a production-hardened xray.json configuration.
func RenderXrayConfig(
	portPrimary int,
	portHigh int,
	sni string,
	dest string,
	realityPrivKey string,
	shortIDs []string,
	clients []XrayClient,
) ([]byte, error) {
	if portPrimary <= 0 {
		portPrimary = 443
	}
	if sni == "" {
		sni = DefaultDecoyDomain
	}
	if IsBlacklistedDecoyDomain(sni) {
		return nil, fmt.Errorf("decoy domain %q is blacklisted as a known censor target", sni)
	}
	if dest == "" {
		dest = net.JoinHostPort(sni, "443")
	} else if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "443")
	}
	if len(shortIDs) == 0 {
		pool, err := GenerateShortIDPool(8)
		if err != nil {
			return nil, err
		}
		shortIDs = pool
	}

	cfg := XrayConfig{
		Log: XrayLog{
			LogLevel: "none",
		},
		Inbounds: []XrayInbound{
			{
				Port:     portPrimary,
				Protocol: "vless",
				Settings: XrayInboundSettings{
					Clients:    clients,
					Decryption: "none",
				},
				StreamSettings: XrayStreamSettings{
					Network:  "tcp",
					Security: "reality",
					RealitySettings: XrayRealitySettings{
						Show:        false,
						Dest:        dest,
						Xver:        0,
						ServerNames: []string{sni},
						PrivateKey:  realityPrivKey,
						ShortIDs:    shortIDs,
					},
				},
			},
		},
		Outbounds: []XrayOutbound{
			{
				Protocol: "freedom",
				Tag:      "direct",
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// ParseXrayConfig decodes an existing config.json and validates REALITY private keys and short IDs.
func ParseXrayConfig(data []byte) (*XrayConfig, error) {
	var cfg XrayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal xray config: %w", err)
	}
	for i, inbound := range cfg.Inbounds {
		stream := inbound.StreamSettings
		for j, shortID := range stream.RealitySettings.ShortIDs {
			if len(shortID) > 16 || len(shortID)%2 != 0 {
				return nil, fmt.Errorf(
					"validate reality short ID %d for inbound %d: must be even-length hex with at most 16 characters",
					j,
					i,
				)
			}
			if _, err := hex.DecodeString(shortID); err != nil {
				return nil, fmt.Errorf("validate reality short ID %d for inbound %d: %w", j, i, err)
			}
		}
		if stream.Security != "reality" && stream.RealitySettings.PrivateKey == "" {
			continue
		}
		if _, err := DerivePublicKey(stream.RealitySettings.PrivateKey); err != nil {
			return nil, fmt.Errorf("validate reality private key for inbound %d: %w", i, err)
		}
	}
	return &cfg, nil
}

// BuildVLESSURI constructs a standard client vless:// URI.
func BuildVLESSURI(
	host string,
	port int,
	clientID string,
	name string,
	sni string,
	pbk string,
	sid string,
	flow string,
	opts ...bool,
) (string, error) {
	if host == "" {
		return "", errors.New("host cannot be empty")
	}
	if port <= 0 {
		port = 443
	}
	if clientID == "" {
		return "", errors.New("clientID cannot be empty")
	}
	if sni == "" {
		sni = DefaultDecoyDomain
	}

	mux := false
	if len(opts) > 0 && opts[0] {
		mux = true
	}

	query := url.Values{}
	query.Set("security", "reality")
	query.Set("encryption", "none")
	query.Set("pbk", pbk)
	query.Set("headerType", "none")
	query.Set("fp", "chrome")
	query.Set("sni", sni)
	query.Set("sid", sid)
	query.Set("type", "tcp")
	if flow != "" && flow != "none" {
		query.Set("flow", flow)
	}
	if mux {
		query.Set("mux", "true")
	}

	u := url.URL{
		Scheme:   "vless",
		User:     url.User(clientID),
		Host:     net.JoinHostPort(host, strconv.Itoa(port)),
		RawQuery: query.Encode(),
		Fragment: name,
	}

	return u.String(), nil
}
