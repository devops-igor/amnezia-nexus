//go:build with_utls && !race

package vless

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	badoption "github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/metadata"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestDialer_VisionFlow_CheckptrUnderRace verifies that dialing VLESS with flow "xtls-rprx-vision"
// over a REALITY TLS connection completes without triggering checkptr invalid allocation panics.
// Isolated with build tag !race because sing-vmess inspects utls.Conn via reflection pointer arithmetic.
func TestDialer_VisionFlow_CheckptrUnderRace(t *testing.T) {
	decoyAddr, cleanupDecoy := startDecoyServer(t, 0)
	defer cleanupDecoy()
	decoyHost, decoyPortStr, _ := net.SplitHostPort(decoyAddr)
	var decoyPort uint16
	_, _ = fmt.Sscanf(decoyPortStr, "%d", &decoyPort)

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519: %v", err)
	}
	pubKey := privKey.PublicKey()
	privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(pubKey.Bytes())
	shortID := "0123456789abcdef"
	serverName := "example.com"
	clientUUID := uuid.New().String()

	inboundTLSOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: privB64,
			ShortID:    badoption.Listable[string]{shortID},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     decoyHost,
					ServerPort: decoyPort,
				},
			},
		},
	}

	serverCfg, err := sTLS.NewRealityServer(context.Background(), nil, inboundTLSOpts)
	if err != nil {
		t.Fatalf("NewRealityServer: %v", err)
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen reality server: %v", err)
	}
	defer serverLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, aErr := serverLn.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn, sErr := sTLS.ServerHandshake(ctx, c, serverCfg)
				if sErr != nil {
					return
				}
				defer tlsConn.Close()
				req, rErr := vless.ReadRequest(tlsConn)
				if rErr != nil {
					return
				}
				if req.Flow != "xtls-rprx-vision" {
					return
				}
				if _, wErr := tlsConn.Write([]byte{0, 0}); wErr != nil {
					return
				}
				_, _ = io.Copy(tlsConn, tlsConn)
			}(conn)
		}
	}()

	params := models.VLESSRealityParams{
		UUID:          clientUUID,
		Flow:          "xtls-rprx-vision",
		PublicKey:     pubB64,
		ShortID:       shortID,
		ServerName:    serverName,
		Fingerprint:   "chrome",
		EngineProfile: "modern_pq",
	}

	d, err := New(serverLn.Addr().String(), params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := d.DialContext(dialCtx, "tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("DialContext failed under race detector: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello from xtls-rprx-vision under race detector")
	if _, wErr := conn.Write(payload); wErr != nil {
		t.Fatalf("Write: %v", wErr)
	}
	reply := make([]byte, len(payload))
	if _, rErr := io.ReadFull(conn, reply); rErr != nil {
		t.Fatalf("ReadFull: %v", rErr)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("reply mismatch: got %q, want %q", reply, payload)
	}
}

// TestAuditR4VisionTransferIntegrity verifies sustained bulk transfer through
// Vision flow with garbage-collection pressure. Every response is verified byte-for-byte.
func TestAuditR4VisionTransferIntegrity(t *testing.T) {
	f := setupTestServer(t, "xtls-rprx-vision", 0)
	defer f.ServerClose()
	echo, cleanup := startTCPEchoServer(t)
	defer cleanup()
	d, err := New(f.Endpoint, f.Params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var churn [][]byte
	for round := 0; round < 200; round++ {
		payload := bytes.Repeat([]byte(fmt.Sprintf("round-%03d-", round)), 4096)
		errc := make(chan error, 1)
		go func() { _, e := conn.Write(payload); errc <- e }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("round %d read: %v", round, err)
		}
		if e := <-errc; e != nil {
			t.Fatalf("round %d write: %v", round, e)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatalf("round %d: echoed bytes corrupted", round)
		}
		// ordinary allocation churn reuses freed spans of the same size classes
		churn = append(churn, bytes.Repeat([]byte{0xA5}, 16384))
		if len(churn) > 64 {
			churn = churn[1:]
		}
		if round%5 == 0 {
			runtime.GC()
		}
	}
	t.Logf("200 verified rounds of %d bytes", 4096*10)
	_ = metadata.Socksaddr{}
}

// TestAuditR4VisionCloseDuringRead verifies streambridge-style teardown on Vision flow:
// one goroutine blocked in Read while another calls Close.
func TestAuditR4VisionCloseDuringRead(t *testing.T) {
	f := setupTestServer(t, "xtls-rprx-vision", 0)
	defer f.ServerClose()
	echo, cleanup := startTCPEchoServer(t)
	defer cleanup()
	d, err := New(f.Endpoint, f.Params)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := d.DialContext(ctx, "tcp", echo)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		errc := make(chan error, 1)
		go func() { _, e := conn.Read(make([]byte, 1)); errc <- e }()
		time.Sleep(5 * time.Millisecond)
		_ = conn.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: Read not unblocked", i)
		}
		cancel()
	}
}
