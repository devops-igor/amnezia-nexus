package clientawg

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
	"golang.org/x/crypto/curve25519"
)

func testKeys(seed byte) (string, string) {
	key := [32]byte{seed}
	public, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(public)
}

func testConfig() Config {
	private, public := testKeys(17)
	_, peer := testKeys(33)
	return Config{PrivateKey: private, PublicKey: public, TUN: virtualtun.Config{Name: "test", MTU: 1280}, Peers: []Peer{{PublicKey: peer, AllowedIP: netip.MustParsePrefix("10.40.0.2/32")}}}
}

func TestValidateRejectsUnsafeSnapshots(t *testing.T) {
	tests := map[string]func(*Config){
		"malformed private":   func(c *Config) { c.PrivateKey = "sensitive\nlisten_port=5" },
		"zero private":        func(c *Config) { c.PrivateKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"mismatched identity": func(c *Config) { _, c.PublicKey = testKeys(49) },
		"noncanonical public": func(c *Config) { c.PublicKey += "\n" },
		"negative port":       func(c *Config) { c.ListenPort = -1 },
		"large port":          func(c *Config) { c.ListenPort = 65536 },
		"invalid MTU":         func(c *Config) { c.TUN.MTU = 0 },
		"invalid queue":       func(c *Config) { c.TUN.OutboundCapacity = -1 },
		"duplicate key":       func(c *Config) { c.Peers = append(c.Peers, c.Peers[0]) },
		"duplicate IP": func(c *Config) {
			_, key := testKeys(49)
			c.Peers = append(c.Peers, Peer{PublicKey: key, AllowedIP: c.Peers[0].AllowedIP})
		},
		"self peer":               func(c *Config) { c.Peers[0].PublicKey = c.PublicKey },
		"invalid peer key":        func(c *Config) { c.Peers[0].PublicKey = "dummy" },
		"low order peer":          func(c *Config) { key := [32]byte{1}; c.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(key[:]) },
		"broad address":           func(c *Config) { c.Peers[0].AllowedIP = netip.MustParsePrefix("10.40.0.0/24") },
		"IPv6 address":            func(c *Config) { c.Peers[0].AllowedIP = netip.MustParsePrefix("2001:db8::1/128") },
		"multicast address":       func(c *Config) { c.Peers[0].AllowedIP = netip.MustParsePrefix("224.0.0.1/32") },
		"overlap headers":         func(c *Config) { c.Parameters.H1 = "2-3" },
		"malformed header":        func(c *Config) { c.Parameters.H1 = "secret\nprivate_key=secret" },
		"full range":              func(c *Config) { c.Parameters.H1 = "0-4294967295" },
		"negative padding":        func(c *Config) { c.Parameters.S4 = -1 },
		"overflow padding":        func(c *Config) { c.Parameters.S1 = 65536 },
		"invalid HP":              func(c *Config) { c.Parameters.HeaderProtectionKey = "secret" },
		"HP lacks nonce":          func(c *Config) { c.Parameters.HeaderProtectionKey = c.PrivateKey },
		"invalid content padding": func(c *Config) { c.Parameters.ContentPaddingAddition = "secret" },
		"excess content padding":  func(c *Config) { c.Parameters.ContentPaddingAddition = "0-4294967295" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			change(&cfg)
			dev, err := NewDevice(cfg)
			if dev != nil {
				_ = dev.Close()
				t.Fatal("invalid snapshot started device")
			}
			if err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), cfg.PrivateKey) {
				t.Fatal("error exposed configuration")
			}
		})
	}
}

func TestPeerLifecycleAndClose(t *testing.T) {
	cfg := testConfig()
	d, err := NewDevice(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	status, err := d.Status()
	if err != nil || status.ListenPort == 0 || len(status.Peers) != 1 || status.Peers[0].AllowedIP != cfg.Peers[0].AllowedIP {
		t.Fatalf("startup status mismatch: %+v %v", status, err)
	}
	if err := d.AddPeer(cfg.Peers[0]); !errors.Is(err, ErrPeerExists) {
		t.Fatalf("duplicate: %v", err)
	}
	_, key := testKeys(49)
	peer := Peer{PublicKey: key, AllowedIP: netip.MustParsePrefix("10.40.0.3/32")}
	if err := d.UpdatePeer(peer); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("missing update: %v", err)
	}
	if err := d.AddPeer(peer); err != nil {
		t.Fatal(err)
	}
	duplicate := peer
	duplicate.AllowedIP = cfg.Peers[0].AllowedIP
	if err := d.UpdatePeer(duplicate); err == nil {
		t.Fatal("stole assigned IP")
	}
	peer.AllowedIP = netip.MustParsePrefix("10.40.0.4/32")
	if err := d.UpdatePeer(peer); err != nil {
		t.Fatal(err)
	}
	status, err = d.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range status.Peers {
		if p.PublicKey == peer.PublicKey && p.AllowedIP != peer.AllowedIP {
			t.Fatal("update failed")
		}
	}
	if err := d.RemovePeer(peer.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := d.RemovePeer(peer.PublicKey); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("repeat removal: %v", err)
	}
	received := make(chan error, 1)
	go func() { _, err := d.ReceiveOutbound(); received <- err }()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _ = d.Close() })
	}
	wg.Wait()
	select {
	case err := <-received:
		if !errors.Is(err, virtualtun.ErrClosed) {
			t.Fatalf("receive: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not unblock receiver")
	}
	if _, err := d.Status(); !errors.Is(err, ErrClosed) {
		t.Fatalf("status after close: %v", err)
	}
	if err := d.AddPeer(peer); !errors.Is(err, ErrClosed) {
		t.Fatalf("add after close: %v", err)
	}
	if err := d.InjectInbound([]byte{1}); !errors.Is(err, virtualtun.ErrClosed) {
		t.Fatalf("inject after close: %v", err)
	}
}

func TestFailedListenerStartupReleasesResources(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.ListenPort = occupied.LocalAddr().(*net.UDPAddr).Port
	d, err := NewDevice(cfg)
	if err == nil {
		_ = d.Close()
		t.Fatal("occupied port accepted")
	}
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = NewDevice(cfg)
	if err != nil {
		t.Fatalf("restart after failure: %v", err)
	}
	_ = d.Close()
}

func TestConcurrentPeerStatusAndClose(t *testing.T) {
	d, err := NewDevice(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			_, key := testKeys(byte(65 + i*8))
			p := Peer{PublicKey: key, AllowedIP: netip.MustParsePrefix(fmt.Sprintf("10.40.1.%d/32", i+1))}
			_ = d.AddPeer(p)
			_, _ = d.Status()
			_ = d.UpdatePeer(p)
			_ = d.RemovePeer(key)
		})
	}
	wg.Go(func() { _ = d.Close() })
	wg.Wait()
}

func TestStatusAllowlistAndErrorsHideSecrets(t *testing.T) {
	_, key := testKeys(49)
	rawKey, _ := base64.StdEncoding.DecodeString(key)
	raw := "private_key=private-secret\nheader_protection_key=hp-secret\nlisten_port=1234\npublic_key=" + hex.EncodeToString(rawKey) + "\npreshared_key=psk-secret\nallowed_ip=10.40.0.2/32\nendpoint=127.0.0.1:2345\nlast_handshake_time_sec=42\nlast_handshake_time_nsec=99\nrx_bytes=10\ntx_bytes=20\n"
	status, err := parseStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Peers) != 1 || status.Peers[0].ReceiveBytes != 10 || status.Peers[0].TransmitBytes != 20 || status.Peers[0].LastHandshake != time.Unix(42, 99) {
		t.Fatalf("bad public status: %+v", status)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("status leaked secret")
	}
	for _, line := range []string{"listen_port=private-secret", "public_key=private-secret", "public_key=" + hex.EncodeToString(rawKey) + "\nrx_bytes=private-secret"} {
		_, err := parseStatus(line)
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("parser did not sanitize error")
		}
	}
}
