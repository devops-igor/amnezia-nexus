package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
)

// ProxyStreamDialer is the outbound stream egress of a proxy backend device: the
// same dialer the device splices client flows onto. An authenticated exchange
// opened here traverses the live tunnel; it does not consume the device's single
// return reader.
type ProxyStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ProxyStreamDevice is implemented by a proxy backend PacketDevice that exposes
// its real egress so in-tunnel health can perform a protocol-appropriate
// application exchange through the path client traffic actually uses.
//
// It exists because the packet canary contract is not satisfiable by these
// transports: streambridge carries no ICMP (streambridge/doc.go) and Naive
// tunnels TCP only (naive/dialer.go). Answering health with a real authenticated
// request/reply over the device's own egress is the protocol-appropriate proof of
// data-plane readiness, and it needs no second reader on the device.
type ProxyStreamDevice interface {
	ProxyEgress() ProxyStreamDialer
}

// ErrNoProxyEgress is returned when a proxy device cannot supply the egress its
// health exchange requires.
var ErrNoProxyEgress = errors.New("proxy device exposes no stream egress")

// SetProxyCanaryDestinationForTest points the proxy payload canary at an explicit
// destination so a local fixture can serve the exchange. It overrides only the
// address; the exchange itself, and therefore the pass/fail decision, remains the
// real one. Production never calls this, so the destination stays derived from the
// tunnel's own parameters.
func (hp *HealthProber) SetProxyCanaryDestinationForTest(destination string) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.proxyCanaryDestination = destination
}

// proxyPayloadCanary is the parsed destination of a proxy payload canary. By
// default the destination is exactly the one the F10 qualification exchange
// already proves, so a backend qualified on a real request/reply is health-checked
// on the same real request/reply and no additional allowed destination is
// introduced.
type proxyPayloadCanary struct {
	proto string
	raw   json.RawMessage
	// destination overrides the protocol-derived destination; empty in production.
	destination string
}

// newProxyPayloadCanary decides whether a tunnel's transport can answer an inner
// canary only with a protocol-appropriate application exchange, and parses the
// parameters needed to build it. It reports ok=false for transports the unchanged
// packet canary already serves (AWG and unknown protocols).
func newProxyPayloadCanary(tunnel *models.BackendTunnel, destination string) (proxyPayloadCanary, bool) {
	if tunnel == nil || len(tunnel.ProtocolParams) == 0 || tunnel.Endpoint == "" {
		return proxyPayloadCanary{}, false
	}
	switch proto := models.NormalizeTunnelProtocol(tunnel.Protocol); proto {
	case models.ProtocolVLESS, models.ProtocolNaive:
		return proxyPayloadCanary{
			proto:       proto,
			raw:         tunnel.ProtocolParams,
			destination: destination,
		}, true
	default:
		return proxyPayloadCanary{}, false
	}
}

// probeVLESSViaEgress performs the authenticated VLESS exchange for canary's
// tunnel over the supplied egress, honoring a destination override.
func probeVLESSViaEgress(ctx context.Context, egress ProxyStreamDialer, canary proxyPayloadCanary, timeout time.Duration) error {
	var params models.VLESSRealityParams
	if err := json.Unmarshal(canary.raw, &params); err != nil {
		return fmt.Errorf("vless: invalid protocol params: %w", err)
	}
	if canary.destination != "" {
		_, err := vless.ProbeVLESSTrafficViaDialerTo(ctx, egress, params, canary.destination, timeout)
		return err
	}
	_, err := vless.ProbeVLESSTrafficViaDialer(ctx, egress, params, timeout)
	return err
}

// probeNaiveViaEgress performs the authenticated Naive exchange for canary's
// tunnel over the supplied egress, honoring a destination override.
func probeNaiveViaEgress(ctx context.Context, egress ProxyStreamDialer, canary proxyPayloadCanary, timeout time.Duration) error {
	var params models.NaiveProxyParams
	if err := json.Unmarshal(canary.raw, &params); err != nil {
		return fmt.Errorf("naive: invalid protocol params: %w", err)
	}
	if canary.destination != "" {
		_, err := naive.ProbeNaiveTrafficViaDialerTo(ctx, egress, params, canary.destination, timeout)
		return err
	}
	_, err := naive.ProbeNaiveTrafficViaDialer(ctx, egress, params, timeout)
	return err
}

// probeProxyPayloadCanary runs the authenticated application exchange for the
// canary's protocol over egress. It reports failure for an unproven payload path
// and performs no handshake-only fallback.
func probeProxyPayloadCanary(ctx context.Context, egress ProxyStreamDialer, canary proxyPayloadCanary, timeout time.Duration) error {
	if egress == nil {
		return ErrNoProxyEgress
	}
	if timeout <= 0 {
		timeout = defaultProxyQualifyTimeout
	}

	switch canary.proto {
	case models.ProtocolVLESS:
		return probeVLESSViaEgress(ctx, egress, canary, timeout)
	case models.ProtocolNaive:
		return probeNaiveViaEgress(ctx, egress, canary, timeout)
	default:
		return fmt.Errorf("protocol %s has no proxy payload canary", canary.proto)
	}
}

// probeProxyDeviceCanary performs the protocol-appropriate authenticated
// application exchange for an actual proxy backend device. It is the proxy branch
// of defaultCanaryProbe: a proxy device that cannot expose a usable egress, or a
// tunnel without the parameters an exchange needs, fails closed rather than
// falling back to a packet canary its transport cannot carry.
func probeProxyDeviceCanary(ctx context.Context, dev PacketDevice, tunnel *models.BackendTunnel, timeout time.Duration, destination string) error {
	psd, ok := dev.(ProxyStreamDevice)
	if !ok {
		return fmt.Errorf("proxy backend device of type %T does not expose its stream egress", dev)
	}
	canary, ok := newProxyPayloadCanary(tunnel, destination)
	if !ok {
		return fmt.Errorf("proxy backend tunnel %d lacks the protocol parameters or endpoint its payload canary requires", tunnel.ID)
	}
	return probeProxyPayloadCanary(ctx, psd.ProxyEgress(), canary, timeout)
}
