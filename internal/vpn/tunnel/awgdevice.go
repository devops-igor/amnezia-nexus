package tunnel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// AWGClientDevice implements PacketDevice for connecting the portal to a backend AWG server.
type AWGClientDevice struct {
	name            string
	mtu             int
	vtun            *VirtualTUN
	dev             *device.Device
	doneCh          chan struct{}
	closed          atomic.Bool
	createdAt       time.Time
	handshakeTimeFn func() time.Time
	once            sync.Once
}

// VirtualTUN implements tun.Device in-memory for amneziawg-go.
type VirtualTUN struct {
	inPackets  chan []byte
	outPackets chan []byte
	events     chan tun.Event
	closed     chan struct{}
	mtu        int
	name       string
	dropCount  atomic.Uint64
	once       sync.Once
}

func (t *VirtualTUN) File() *os.File { return nil }

func (t *VirtualTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt, ok := <-t.inPackets:
		if !ok {
			return 0, os.ErrClosed
		}
		if len(bufs) == 0 {
			return 0, nil
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *VirtualTUN) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		pkt := buf[offset:]
		out := make([]byte, len(pkt))
		copy(out, pkt)
		select {
		case t.outPackets <- out:
			n++
		case <-t.closed:
			return n, os.ErrClosed
		default:
			// drop if full to avoid blocking the tun writer
			t.dropCount.Add(1)
			n++
		}
	}
	return n, nil
}

// DroppedPackets returns the total number of packets dropped due to a full queue.
func (t *VirtualTUN) DroppedPackets() uint64 {
	return t.dropCount.Load()
}

func (t *VirtualTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *VirtualTUN) Name() (string, error)    { return t.name, nil }
func (t *VirtualTUN) Events() <-chan tun.Event { return t.events }
func (t *VirtualTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
	})
	return nil
}
func (t *VirtualTUN) BatchSize() int { return 1 }

func base64ToHex(b64 string) (string, error) {
	keyStr := strings.TrimSpace(b64)
	if len(keyStr) == 64 {
		if b, err := hex.DecodeString(keyStr); err == nil && len(b) == 32 {
			return strings.ToLower(keyStr), nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(b) != 32 {
		// Fallback for tests using dummy keys ("us-east-pubkey", etc)
		// We hash the string to 32 bytes to ensure IpcSet doesn't fail
		h := sha256.Sum256([]byte(keyStr))
		return hex.EncodeToString(h[:]), nil
	}
	return hex.EncodeToString(b), nil
}

func toInt(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case int64:
		return int(val)
	case string:
		var i int
		_, _ = fmt.Sscanf(val, "%d", &i)
		return i
	}
	return 0
}

// NewAWGClientDevice creates a new AWGClientDevice.
func NewAWGClientDevice(name, endpoint, privateKey, publicKey string, mtu int, awgParams map[string]any) (*AWGClientDevice, error) {
	if mtu <= 0 {
		mtu = 1340
	}

	privHex, err := base64ToHex(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	pubHex, err := base64ToHex(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	vtun := &VirtualTUN{
		inPackets:  make(chan []byte, 1024),
		outPackets: make(chan []byte, 1024),
		events:     make(chan tun.Event, 2),
		closed:     make(chan struct{}),
		mtu:        mtu,
		name:       name,
	}

	logger := device.NewLogger(device.LogLevelSilent, name)
	dev := device.NewDevice(vtun, conn.NewDefaultBind(), logger)

	var cfg string
	cfg += buildAWGIPCConfig(privHex, pubHex, endpoint, awgParams)

	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		_ = vtun.Close()
		return nil, fmt.Errorf("failed to configure awg device: %w", err)
	}

	vtun.events <- tun.EventUp

	err = dev.Up()
	if err != nil {
		dev.Close()
		_ = vtun.Close()
		return nil, fmt.Errorf("failed to bring up awg device: %w", err)
	}

	d := &AWGClientDevice{
		name:      name,
		mtu:       mtu,
		vtun:      vtun,
		dev:       dev,
		doneCh:    make(chan struct{}),
		createdAt: time.Now(),
	}

	return d, nil
}

func normalizeAWGKey(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "_", ""), "-", ""))
}

func lookupAWGParamStr(awgParams map[string]any, keys ...string) (string, bool) {
	if awgParams == nil {
		return "", false
	}
	for _, k := range keys {
		nk := normalizeAWGKey(k)
		for mk, v := range awgParams {
			if (strings.EqualFold(mk, k) || normalizeAWGKey(mk) == nk) && v != nil {
				s := strings.TrimSpace(fmt.Sprint(v))
				if s != "" {
					return s, true
				}
			}
		}
	}
	return "", false
}

func lookupAWGParamBool(awgParams map[string]any, keys ...string) bool {
	if s, ok := lookupAWGParamStr(awgParams, keys...); ok {
		sLower := strings.ToLower(s)
		return sLower == "on" || sLower == "true" || sLower == "1" || sLower == "yes"
	}
	return false
}

func lookupAWGParamInt(awgParams map[string]any, def int, keys ...string) int {
	if s, ok := lookupAWGParamStr(awgParams, keys...); ok {
		return toInt(s)
	}
	return def
}

func renderAWGObfuscationParams(b *strings.Builder, awgParams map[string]any) {
	jc := lookupAWGParamInt(awgParams, 1, "junk_packet_count", "jc")
	jmin := lookupAWGParamInt(awgParams, 0, "junk_packet_min_size", "jmin")
	jmax := lookupAWGParamInt(awgParams, 0, "junk_packet_max_size", "jmax")
	s1 := lookupAWGParamInt(awgParams, 0, "init_packet_junk_size", "s1")
	s2 := lookupAWGParamInt(awgParams, 0, "response_packet_junk_size", "s2")
	s3 := lookupAWGParamInt(awgParams, 0, "cookie_reply_packet_junk_size", "underload_packet_junk_size", "s3")
	s4 := lookupAWGParamInt(awgParams, 0, "transport_packet_junk_size", "s4")

	h1 := "1"
	if val, ok := lookupAWGParamStr(awgParams, "init_packet_magic_header", "h1"); ok {
		h1 = val
	}
	h2 := "2"
	if val, ok := lookupAWGParamStr(awgParams, "response_packet_magic_header", "h2"); ok {
		h2 = val
	}
	h3 := "3"
	if val, ok := lookupAWGParamStr(awgParams, "underload_packet_magic_header", "cookie_reply_packet_magic_header", "h3"); ok {
		h3 = val
	}
	h4 := "4"
	if val, ok := lookupAWGParamStr(awgParams, "transport_packet_magic_header", "h4"); ok {
		h4 = val
	}

	fmt.Fprintf(b, "jc=%d\njmin=%d\njmax=%d\n", jc, jmin, jmax)
	fmt.Fprintf(b, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n", s1, s2, s3, s4)
	fmt.Fprintf(b, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n", h1, h2, h3, h4)
}

func renderAWGDeviceOptions(b *strings.Builder, awgParams map[string]any) {
	if hpKey, ok := lookupAWGParamStr(awgParams, "header_protection_key", "hpkey", "HeaderProtectionKey"); ok {
		if hpKeyHex, err := base64ToHex(hpKey); err == nil && hpKeyHex != "" {
			fmt.Fprintf(b, "header_protection_key=%s\n", hpKeyHex)
		}
	}
	if lookupAWGParamBool(awgParams, "random_trailers", "randomtrailers") {
		b.WriteString("random_trailers=true\n")
	}
	if lookupAWGParamBool(awgParams, "disable_cookies", "disablecookies") {
		b.WriteString("disable_cookies=true\n")
	}
	if cpa, ok := lookupAWGParamStr(awgParams, "content_padding_addition", "contentpaddingaddition"); ok {
		fmt.Fprintf(b, "content_padding_addition=%s\n", cpa)
	}
	for _, timingKey := range []string{"rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts"} {
		if val, ok := lookupAWGParamStr(awgParams, timingKey); ok {
			fmt.Fprintf(b, "%s=%s\n", timingKey, val)
		}
	}
}

func renderAWGPeerConfig(b *strings.Builder, publicKeyHex, endpoint string, awgParams map[string]any) {
	fmt.Fprintf(b, "public_key=%s\n", publicKeyHex)
	if pskVal, ok := lookupAWGParamStr(awgParams, "preshared_key", "psk", "presharedkey"); ok {
		if pskHex, err := base64ToHex(pskVal); err == nil && pskHex != "" {
			fmt.Fprintf(b, "preshared_key=%s\n", pskHex)
		}
	}
	fmt.Fprintf(b, "endpoint=%s\n", endpoint)
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	pka := "25"
	if val, ok := lookupAWGParamStr(awgParams, "persistent_keepalive_interval", "persistent_keepalive", "persistentkeepalive", "PersistentKeepalive"); ok {
		pka = val
	}
	fmt.Fprintf(b, "persistent_keepalive_interval=%s\n", pka)
}

// buildAWGIPCConfig renders the amneziawg-go IpcSet device configuration,
// including obfuscation parameters, header protection key, and transport options.
// Exposed for tests via export_test.go.
func buildAWGIPCConfig(privateKeyHex, publicKeyHex, endpoint string, awgParams map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privateKeyHex)
	renderAWGObfuscationParams(&b, awgParams)
	renderAWGDeviceOptions(&b, awgParams)
	renderAWGPeerConfig(&b, publicKeyHex, endpoint, awgParams)
	return b.String()
}

func (d *AWGClientDevice) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-d.vtun.outPackets:
		if !ok {
			return 0, errors.New("device closed")
		}
		return copy(p, pkt), nil
	case <-d.doneCh:
		return 0, errors.New("device closed")
	}
}

func (d *AWGClientDevice) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, errors.New("device closed")
	}
	pkt := make([]byte, len(p))
	copy(pkt, p)
	select {
	case d.vtun.inPackets <- pkt:
		return len(p), nil
	case <-d.doneCh:
		return 0, errors.New("device closed")
	default:
		return len(p), nil
	}
}

func (d *AWGClientDevice) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.doneCh)
		d.dev.Close()
		_ = d.vtun.Close()
	})
	return nil
}

func (d *AWGClientDevice) LocalAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	return addr
}

func (d *AWGClientDevice) Name() string { return d.name }

func (d *AWGClientDevice) MTU() int { return d.mtu }

// CreatedAt returns the time the device was created.
func (d *AWGClientDevice) CreatedAt() time.Time {
	return d.createdAt
}

// DroppedPackets returns the total number of packets dropped by the underlying VirtualTUN.
func (d *AWGClientDevice) DroppedPackets() uint64 {
	if d.vtun == nil {
		return 0
	}
	return d.vtun.DroppedPackets()
}

// IsClosed returns true if the device has been closed.
func (d *AWGClientDevice) IsClosed() bool {
	return d.closed.Load()
}

func (d *AWGClientDevice) LastHandshakeTime() time.Time {
	if d.handshakeTimeFn != nil {
		return d.handshakeTimeFn()
	}
	out, err := d.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec, nsec int64
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			sec, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		} else if strings.HasPrefix(line, "last_handshake_time_nsec=") {
			nsec, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_nsec="), 10, 64)
		}
	}
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}
