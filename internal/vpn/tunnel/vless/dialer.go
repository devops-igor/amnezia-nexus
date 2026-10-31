//go:build with_utls

package vless

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Dialer connects to a VLESS+REALITY endpoint and establishes encrypted streams
// satisfying streambridge.StreamDialer.
type Dialer struct {
	endpoint string
	tlsCfg   tls.Config
	client   *vless.Client
	nd       net.Dialer
}

// New constructs a new VLESS+REALITY Dialer with defensive input validation.
func New(endpoint string, p models.VLESSRealityParams) (*Dialer, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return nil, errors.New("vless: endpoint host cannot be empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("vless: invalid endpoint port %q", portStr)
	}

	parsedUUID, err := uuid.Parse(p.UUID)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid uuid: %w", err)
	}

	if len(p.ShortID) > 16 {
		return nil, errors.New("vless: short_id exceeds 16 hex characters")
	}
	if len(p.ShortID) > 0 {
		var sid [8]byte
		if _, err := hex.Decode(sid[:], []byte(p.ShortID)); err != nil {
			return nil, fmt.Errorf("vless: invalid short_id: %w", err)
		}
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(p.PublicKey)
	if err != nil {
		if b, errStd := base64.StdEncoding.DecodeString(p.PublicKey); errStd == nil && len(b) == 32 {
			pubKeyBytes = b
		} else if b, errURL := base64.URLEncoding.DecodeString(p.PublicKey); errURL == nil && len(b) == 32 {
			pubKeyBytes = b
		} else if b, errRawStd := base64.RawStdEncoding.DecodeString(p.PublicKey); errRawStd == nil && len(b) == 32 {
			pubKeyBytes = b
		} else {
			return nil, fmt.Errorf("vless: invalid public_key: %w", err)
		}
	}
	if len(pubKeyBytes) != 32 {
		return nil, errors.New("vless: public_key must be 32 bytes")
	}
	normPubKey := base64.RawURLEncoding.EncodeToString(pubKeyBytes)

	switch p.Flow {
	case "", "xtls-rprx-vision":
	default:
		return nil, fmt.Errorf("vless: unsupported flow: %s", p.Flow)
	}

	fp := p.Fingerprint
	if fp == "" {
		fp = "chrome"
	}

	tlsOpts := option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: p.ServerName,
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: normPubKey,
			ShortID:   p.ShortID,
		},
	}

	tlsCfg, err := tls.NewClient(context.Background(), nil, host, tlsOpts)
	if err != nil {
		return nil, fmt.Errorf("vless: tls client config: %w", err)
	}

	vlessClient, err := vless.NewClient(parsedUUID.String(), p.Flow, logger.NOP())
	if err != nil {
		return nil, fmt.Errorf("vless: vless client: %w", err)
	}

	return &Dialer{
		endpoint: endpoint,
		tlsCfg:   tlsCfg,
		client:   vlessClient,
		nd:       net.Dialer{},
	}, nil
}

// handshake connects to the endpoint and executes the REALITY TLS handshake.
// Shared by DialContext and probeVLESSReality.
func (d *Dialer) handshake(ctx context.Context) (net.Conn, time.Duration, error) {
	start := time.Now()
	raw, err := d.nd.DialContext(ctx, "tcp", d.endpoint)
	if err != nil {
		return nil, 0, fmt.Errorf("vless: dial: %w", err)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = raw.Close()
	})
	defer stop()

	tc, err := tls.ClientHandshake(ctx, raw, d.tlsCfg)
	if err != nil {
		_ = raw.Close()
		return nil, 0, fmt.Errorf("vless: reality handshake: %w", err)
	}

	return tc, time.Since(start), nil
}

// DialContext establishes an encrypted VLESS connection over REALITY TLS to the target address.
// network must be "tcp" or "udp".
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	tc, _, err := d.handshake(ctx)
	if err != nil {
		return nil, err
	}

	dst := metadata.ParseSocksaddr(address)
	switch network {
	case "tcp":
		conn, err := d.client.DialConn(tc, dst)
		if err != nil {
			_ = tc.Close()
			return nil, fmt.Errorf("vless: dial tcp: %w", err)
		}
		return conn, nil
	case "udp":
		conn, err := d.client.DialEarlyXUDPPacketConn(tc, dst)
		if err != nil {
			_ = tc.Close()
			return nil, fmt.Errorf("vless: dial udp: %w", err)
		}
		return conn, nil
	default:
		_ = tc.Close()
		return nil, net.UnknownNetworkError(network)
	}
}

// SupportsUDP indicates that VLESS supports native UDP packet forwarding.
func (d *Dialer) SupportsUDP() bool {
	return true
}
