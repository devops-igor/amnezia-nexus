package clientawg_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func interopKeys(t *testing.T) (string, string) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private.Bytes()), base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
}

// configToUAPI is only a test adapter for the wg-quick fields emitted by Nexus.
// It translates syntax, never changes the saved configuration's values. Address,
// DNS and MTU are host-interface settings; the in-memory test TUN supplies the MTU.
func configToUAPI(t *testing.T, saved string) string {
	t.Helper()
	names := map[string]string{
		"PrivateKey": "private_key", "PublicKey": "public_key", "PresharedKey": "preshared_key",
		"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
		"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
		"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
		"PersistentKeepalive": "persistent_keepalive_interval", "Endpoint": "endpoint", "ListenPort": "listen_port",
		"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
	}
	var out strings.Builder
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatal("malformed generated config line")
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "Address" || name == "DNS" || name == "MTU" {
			continue
		}
		if name == "AllowedIPs" {
			for _, ip := range strings.Split(value, ",") {
				fmt.Fprintf(&out, "allowed_ip=%s\n", strings.TrimSpace(ip))
			}
			continue
		}
		target, ok := names[name]
		if !ok {
			switch name {
			case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5":
				target = strings.ToLower(name)
			default:
				t.Fatalf("unhandled generated config field %s", name)
			}
		}
		switch name {
		case "PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey":
			key, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(key) != 32 {
				t.Fatalf("invalid generated %s", name)
			}
			value = hex.EncodeToString(key)
		case "RandomTrailers", "DisableCookies":
			if value == "on" {
				value = "true"
			}
			if value == "off" {
				value = "false"
			}
		}
		fmt.Fprintf(&out, "%s=%s\n", target, value)
	}
	return out.String()
}

func startUpstreamClient(t *testing.T, saved string) (*device.Device, *virtualtun.VirtualTUN) {
	t.Helper()
	vt, err := virtualtun.New(virtualtun.Config{Name: "interop-client", MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "interop-client"))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(configToUAPI(t, saved)); err != nil {
		t.Fatal("upstream rejected saved generated configuration")
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return dev, vt
}

func packets(t *testing.T, receive func() ([]byte, error)) <-chan []byte {
	t.Helper()
	out := make(chan []byte, 32)
	go func() {
		defer close(out)
		for {
			packet, err := receive()
			if err != nil {
				return
			}
			select {
			case out <- packet:
			case <-t.Context().Done():
				return
			}
		}
	}()
	return out
}

func udpPacket(src, dst netip.Addr, marker uint32) []byte {
	p := make([]byte, 32)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 40001)
	binary.BigEndian.PutUint16(p[24:26], 12)
	binary.BigEndian.PutUint32(p[28:], marker)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}

// Repetition is application-level UDP traffic, not an S4 startup workaround.
// The HP/S4 test only asserts eventual delivery and explicitly is not a
// first-packet-loss compatibility gate. The S4=0 baseline sends exactly once.
func roundTrip(t *testing.T, server *clientawg.ClientAWGDevice, client *virtualtun.VirtualTUN, serverPackets, clientPackets <-chan []byte, src netip.Addr, repeat bool) {
	t.Helper()
	dst := netip.MustParseAddr("198.51.100.1")
	request, reply := udpPacket(src, dst, 1), udpPacket(dst, src, 2)
	if err := client.InjectInbound(request); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	received := false
	attempts := 1
	for {
		select {
		case p, ok := <-serverPackets:
			if !ok {
				t.Fatal("server TUN closed before delivery")
			}
			if !bytes.Equal(p, request) {
				t.Fatal("server plaintext differs from request")
			}
			received = true
			if err := server.InjectInbound(reply); err != nil {
				t.Fatal(err)
			}
		case p, ok := <-clientPackets:
			if !ok {
				t.Fatal("client TUN closed before delivery")
			}
			if !received || !bytes.Equal(p, reply) {
				t.Fatal("client plaintext differs from reply")
			}
			t.Logf("bidirectional plaintext verified after %d application sends (repeat=%v)", attempts, repeat)
			return
		case <-tick.C:
			if repeat {
				attempts++
				if err := client.InjectInbound(request); err != nil {
					t.Fatal(err)
				}
			}
		case <-deadline.C:
			t.Fatalf("bidirectional plaintext timeout (server received=%v, application sends=%d)", received, attempts)
		}
	}
}

func TestUpstreamClientFirstPacketAndUnknownPeer(t *testing.T) {
	private, public := interopKeys(t)
	clientPrivate, clientPublic := interopKeys(t)
	ip := netip.MustParseAddr("192.0.2.2")
	server, err := clientawg.NewDevice(clientawg.Config{PrivateKey: private, PublicKey: public, TUN: virtualtun.Config{Name: "baseline", MTU: 1280}, Peers: []clientawg.Peer{{PublicKey: clientPublic, AllowedIP: netip.PrefixFrom(ip, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	status, err := server.Status()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := fmt.Sprintf("127.0.0.1:%d", status.ListenPort)
	saved := awg.RenderClientConfig(clientPrivate, ip.String(), public, "", endpoint, "", "", "1280", &awg.AWGParams{}, nil)
	known, vt := startUpstreamClient(t, saved)
	received := packets(t, server.ReceiveOutbound)
	returned := packets(t, vt.ReceiveOutbound)
	roundTrip(t, server, vt, received, returned, ip, false)
	status, err = server.Status()
	if err != nil || len(status.Peers) != 1 || status.Peers[0].LastHandshake.IsZero() || status.Peers[0].ReceiveBytes == 0 || status.Peers[0].TransmitBytes == 0 {
		t.Fatal("missing upstream handshake/traffic status")
	}
	// An authenticated peer cannot claim a different source address.
	if err := vt.InjectInbound(udpPacket(netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.1"), 3)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
		t.Fatal("upstream accepted a spoofed source address")
	case <-time.After(250 * time.Millisecond):
	}
	known.Close()
	unknownPrivate, _ := interopKeys(t)
	unknownSaved := strings.Replace(saved, clientPrivate, unknownPrivate, 1)
	unknown, uvt := startUpstreamClient(t, unknownSaved)
	if err := uvt.InjectInbound(udpPacket(ip, netip.MustParseAddr("198.51.100.1"), 4)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
		t.Fatal("unknown peer reached server plaintext boundary")
	case <-time.After(350 * time.Millisecond):
	}
	raw, err := unknown.IpcGet()
	if err != nil {
		t.Fatal("read unknown client status")
	}
	if !strings.Contains(raw, "last_handshake_time_sec=0\n") {
		t.Fatal("unknown peer completed a handshake")
	}
}

func reservePort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestNexusGeneratedConfigUnchangedAcrossDatabaseAndDeviceRestart(t *testing.T) {
	const secret = "interop-database-secret"
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := database.Open(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	cfg, err := svc.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenPort = reservePort(t)
	cfg.PublicEndpoint = fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)
	if err := svc.UpdateConfig(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(t.Context(), &models.User{Username: "unchanged-config", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	saved, _, err := svc.GenerateClientConfig(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "issued.conf")
	if err := os.WriteFile(configPath, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	for restart := 0; restart < 2; restart++ {
		if restart > 0 {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, openErr := database.Open(path, secret)
			if openErr != nil {
				t.Fatal(openErr)
			}
			db = reopened
		}
		rows, err := db.GetConnectionsByUserID(t.Context(), userID)
		if err != nil || len(rows) != 1 {
			t.Fatal("missing persisted generated connection")
		}
		assigned, ok := rows[0].ClientParams["assigned_ip"].(string)
		if !ok {
			t.Fatal("missing assigned IP")
		}
		ip, err := netip.ParseAddr(assigned)
		if err != nil {
			t.Fatal(err)
		}
		peers := []clientawg.Peer{{PublicKey: rows[0].ClientID, AllowedIP: netip.PrefixFrom(ip, 32)}}
		loaded, err := clientawg.LoadConfig(context.Background(), db, virtualtun.Config{Name: "saved-config", MTU: 1280}, peers)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.PublicKey != cfg.ServerPublicKey || loaded.ListenPort != cfg.ListenPort {
			t.Fatal("persisted portal identity or listen port changed")
		}
		wantParameters := clientawg.Parameters{H1: cfg.H1.String(), H2: cfg.H2.String(), H3: cfg.H3.String(), H4: cfg.H4.String(),
			S1: cfg.S1, S2: cfg.S2, S3: cfg.S3, S4: cfg.S4, HeaderProtectionKey: cfg.HeaderProtectionKey, ContentPaddingAddition: cfg.ContentPaddingAddition}
		if loaded.Parameters != wantParameters || loaded.Parameters.S4 == 0 || loaded.Parameters.HeaderProtectionKey == "" {
			t.Fatal("persisted AWG parameters changed or generated fixture lacks HP/S4 coverage")
		}
		server, err := clientawg.NewDevice(loaded)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		exact, err := os.ReadFile(configPath)
		if err != nil || string(exact) != saved {
			t.Fatal("previously issued config changed")
		}
		client, vt := startUpstreamClient(t, string(exact))
		roundTrip(t, server, vt, packets(t, server.ReceiveOutbound), packets(t, vt.ReceiveOutbound), ip, true)
		client.Close()
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
