package vpn

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/tunnel"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// TestSetProbeFunc_RealProberRunsEvenWithFreshDeviceHandshake pins the
// session-8 fix for issue #43: the SetProbeFunc closure installed by
// NewVPNService must NOT short-circuit to a fake 10ms success when the data
// device's LastHandshakeTime is fresh. That fast path never SENT anything,
// so the real Noise IK prober (the only user of the dedicated probe key) was
// unreachable and the backend's probe peer never handshook. The prober must
// run the real probe (health.ProbeAWGEndpoint) every cycle regardless of
// data-device handshake age — a 10s cadence is trivial load.
//
// RED (before fix): with a fresh data-device handshake the closure returned
// (10ms, nil) without sending, so the mock server observed zero initiations.
// GREEN (after fix): the probe function is health.ProbeAWGEndpoint, the mock
// server receives a genuine Noise IK initiation, and its decrypted static key
// equals the tunnel's dedicated PROBE identity — not the data-device key.
func TestSetProbeFunc_RealProberRunsEvenWithFreshDeviceHandshake(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, serverPubB64, serverPrivB64 := createTestServerAndKey(t, db, "Probe Identity Srv", "127.0.0.1")

	// Pin explicit obfuscation params on the server so resolveTunnelParams
	// uses exactly what the mock responder expects (health.DefaultS1/S2,
	// DefaultH1/H2). Without this, an empty VPNConfig yields S1=0 which
	// overrides the prober default and desynchronizes the mock's framing.
	if err := db.UpdateServer(ctx, sID, map[string]any{
		"protocols": map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": serverPubB64,
				"awg_params": map[string]any{
					"init_packet_magic_header":     health.DefaultH1,
					"response_packet_magic_header": health.DefaultH2,
					"init_packet_junk_size":        health.DefaultS1,
					"response_packet_junk_size":    health.DefaultS2,
				},
			},
		},
	}); err != nil {
		t.Fatalf("failed to pin awg_params on test server: %v", err)
	}

	pc, gotInit, staticCh := startIdentityAWGServer(t, serverPrivB64, health.DefaultS1)

	tun, err := svc.pool.AddTunnel(ctx, sID, pc.LocalAddr().String(), serverPubB64)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// Attach a data device whose handshake is FRESH (10s old) — the
	// always-true branch of the old short-circuit.
	realDev, err := tunnel.NewAWGClientDevice("test-probe-identity", tun.Endpoint, serverPrivB64, serverPubB64, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Now().Add(-10 * time.Second) },
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Issue #43: the identity mock never sends a RESPONSE, so ProbeTunnel is
	// EXPECTED to time out on the response leg. What this test pins is:
	// (1) a real Noise IK initiation reached the mock (no fake-success
	// short-circuit), and (2) its static identity is the dedicated PROBE key.
	// Response verification is covered by the health package's own tests.
	probeDone := make(chan error, 1)
	go func() { _, err := svc.ProbeTunnel(ctx, tun); probeDone <- err }()
	select {
	case <-gotInit:
	case <-time.After(15 * time.Second):
		t.Fatal("no Noise IK initiation reached the mock server (fake-success short-circuit?)")
	}
	<-probeDone // wait for the probe to finish (response timeout is expected)
	gotStatic := <-staticCh

	probePub, err := tunnel.ClientPublicKey(tun)
	if err != nil {
		t.Fatalf("ClientPublicKey failed: %v", err)
	}
	if gotStatic != probePub {
		t.Fatalf("probe used the WRONG identity: got static %q, want probe-key public %q (data key %q)",
			gotStatic, probePub, tun.PublicKey)
	}
	if gotStatic == tun.PublicKey {
		t.Fatalf("probe reused the DATA key identity %q; must use the dedicated probe key", gotStatic)
	}
}

// startIdentityAWGServer is a minimal AWG Noise IK responder that decrypts the
// client STATIC public key from the first valid handshake initiation and
// reports it. Crypto mirrors the mock responder in health/probe_test.go
// (plain, non-header-protected initiation: the test server carries no
// awg_params, so resolveTunnelParams yields an empty HP key).
func startIdentityAWGServer(t *testing.T, serverPrivB64 string, s1 int) (net.PacketConn, chan struct{}, chan string) {
	t.Helper()
	gotInit := make(chan struct{}, 1)
	staticCh := make(chan string, 1)

	serverPriv, err := base64.StdEncoding.DecodeString(serverPrivB64)
	if err != nil {
		t.Fatalf("bad server private key: %v", err)
	}
	serverPubB64, err := health.ComputePublicKeyFromPrivate(serverPrivB64)
	if err != nil {
		t.Fatalf("bad server keypair: %v", err)
	}
	serverPub, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		t.Fatalf("bad server public key: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < s1+116 {
				continue
			}
			msgBody := buf[s1 : s1+116]
			clientEPub := msgBody[8:40]
			encryptedStatic := msgBody[40:88]

			hSum := blake2s.Sum256(append(health.InitialHash[:], serverPub...))
			h := hSum[:]
			hSum = blake2s.Sum256(append(h, clientEPub...))
			h = hSum[:]
			ck := health.KDF1(health.InitialChainKey[:], clientEPub)

			ss1, xerr := curve25519.X25519(serverPriv, clientEPub)
			if xerr != nil {
				continue
			}
			_, k1 := health.KDF2(ck, ss1) // k1 unused: mock decrypts static only
			aead1, aerr := chacha20poly1305.New(k1)
			if aerr != nil {
				continue
			}
			nonce0 := make([]byte, 12)
			staticPub, aerr := aead1.Open(nil, nonce0, encryptedStatic, h)
			if aerr != nil {
				// Not a valid initiation against our keypair; keep listening.
				continue
			}

			select {
			case staticCh <- base64.StdEncoding.EncodeToString(staticPub):
			default:
			}
			select {
			case gotInit <- struct{}{}:
			default:
			}
			// NOTE: do NOT return — the tunnel's data device also sends
			// handshakes to this endpoint (it dials the same mock), and the
			// prober may retry. Keep responding so the probe can complete
			// (the prober waits for a RESPONSE packet, which we don't send
			// here; the probe will time out on the response, but the
			// initiation identity is already captured for assertions).
		}
	}()
	return pc, gotInit, staticCh
}
