//go:build with_utls

package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/google/uuid"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var (
	testCACertPEM []byte
	testLeafCert  tls.Certificate
)

func TestMain(m *testing.M) {
	// Generate in-memory CA and leaf certificate for the decoy server
	caCert, caKey, caPEM, err := generateTestCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test CA: %v\n", err)
		os.Exit(1)
	}
	testCACertPEM = caPEM

	leafCert, err := generateLeafCert(caCert, caKey, "example.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate leaf cert: %v\n", err)
		os.Exit(1)
	}
	testLeafCert = leafCert

	// Setup SSL_CERT_FILE with system certs + test CA so decoy cert is trusted as valid TLS
	tmpDir, err := os.MkdirTemp("", "vless-test-*")
	if err == nil {
		bundlePath := filepath.Join(tmpDir, "ca-bundle.crt")
		var bundleData []byte
		if sysCerts, errRead := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); errRead == nil {
			bundleData = append(bundleData, sysCerts...)
		}
		bundleData = append(bundleData, testCACertPEM...)
		if errWrite := os.WriteFile(bundlePath, bundleData, 0o644); errWrite == nil {
			_ = os.Setenv("SSL_CERT_FILE", bundlePath)
		}
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()
	}

	os.Exit(m.Run())
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"VLESS Test CA"},
			CommonName:   "VLESS Decoy Test CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return parsed, priv, pemBytes, nil
}

func generateLeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  priv,
	}, nil
}

type fixtureHandler struct {
	dialer net.Dialer
}

func (h *fixtureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	target, err := h.dialer.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		_ = target.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		_ = conn.Close()
	}()
	wg.Wait()
}

func (h *fixtureHandler) NewPacketConnectionEx(ctx context.Context, conn network.PacketConn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}

	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer udpTarget.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			buffer := buf.New()
			dest, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			targetAddr := dest.String()
			if targetAddr == "" {
				targetAddr = destination.String()
			}
			udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				buffer.Release()
				continue
			}
			_, _ = udpTarget.WriteTo(buffer.Bytes(), udpAddr)
			buffer.Release()
		}
	}()

	go func() {
		defer wg.Done()
		rawBuf := make([]byte, 65536)
		for {
			n, raddr, err := udpTarget.ReadFrom(rawBuf)
			if err != nil {
				return
			}
			buffer := buf.New()
			buffer.Resize(network.DefaultHeadroom, 0)
			_, _ = buffer.Write(rawBuf[:n])
			fromAddr := metadata.SocksaddrFromNet(raddr)
			if err = conn.WritePacket(buffer, fromAddr); err != nil {
				buffer.Release()
				return
			}
		}
	}()

	<-ctx.Done()
	_ = udpTarget.Close()
	wg.Wait()
}

func startDecoyServer(t *testing.T, delay time.Duration) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for decoy: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testLeafCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsLn := tls.NewListener(ln, tlsConfig)

	closeChan := make(chan struct{})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				select {
				case <-closeChan:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				if delay > 0 {
					time.Sleep(delay)
				}
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
					if tc.ConnectionState().NegotiatedProtocol == "h2" {
						//nolint:staticcheck // SA1019: http2.Server test fixture helper
						h2s := &http2.Server{}
						//nolint:staticcheck // SA1019: http2.Server test fixture helper
						h2s.ServeConn(tc, &http2.ServeConnOpts{
							Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("Hello Decoy!"))
							}),
						})
						return
					}
				}
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Read(buf)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello Decoy!"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	cleanup := func() {
		close(closeChan)
		_ = tlsLn.Close()
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp echo: %v", err)
	}
	closeChan := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(closeChan)
		_ = ln.Close()
	}
}

func startUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp echo: %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
	}
}

func startBlackholeListener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen blackhole: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Keep connection open without writing or reading
			go func(c net.Conn) {
				defer c.Close()
				select {}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
	}
}

type testFixture struct {
	Endpoint    string
	Params      models.VLESSRealityParams
	DecoyAddr   string
	ServerClose func()
}

func setupTestServer(t *testing.T, flow string, decoyDelay time.Duration) *testFixture {
	t.Helper()

	decoyAddr, cleanupDecoy := startDecoyServer(t, decoyDelay)
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

	handler := &fixtureHandler{dialer: net.Dialer{Timeout: 5 * time.Second}}
	vlessService := vless.NewService[int](logger.NOP(), handler)
	vlessService.UpdateUsers([]int{1}, []string{clientUUID}, []string{flow})

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen reality server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn, err := sTLS.ServerHandshake(ctx, c, serverCfg)
				if err != nil {
					_ = c.Close()
					return
				}
				_ = vlessService.NewConnection(ctx, tlsConn, metadata.SocksaddrFromNet(tlsConn.RemoteAddr()), nil)
			}(conn)
		}
	}()

	params := models.VLESSRealityParams{
		UUID:        clientUUID,
		Flow:        flow,
		PublicKey:   pubB64,
		ShortID:     shortID,
		ServerName:  serverName,
		Fingerprint: "chrome",
	}

	return &testFixture{
		Endpoint:  serverLn.Addr().String(),
		Params:    params,
		DecoyAddr: decoyAddr,
		ServerClose: func() {
			cancel()
			_ = serverLn.Close()
			cleanupDecoy()
			wg.Wait()
		},
	}
}
