//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Dialer connects to a VLESS+REALITY endpoint and establishes encrypted streams
// satisfying streambridge.StreamDialer.
type Dialer struct {
	endpoint      string
	client        *vless.Client
	nd            net.Dialer
	serverName    string
	fingerprint   string
	realityPubKey []byte
	shortID       [8]byte
	engineProfile string
}

type realityVerifier struct {
	uConn      *utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("vless: no peer certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok && len(c.authKey) > 0 {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), cert.Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, certBytes := range rawCerts[1:] {
		if intermediate, err := x509.ParseCertificate(certBytes); err == nil {
			opts.Intermediates.AddCert(intermediate)
		}
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
	origConn    *utls.Conn
	offHeapData []byte
	closeOnce   sync.Once
	closeErr    error
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

func (c *realityClientConnWrapper) Close() error {
	c.closeOnce.Do(func() {
		if c.UConn != nil {
			c.closeErr = c.UConn.Close()
		}
		if len(c.offHeapData) > 0 {
			_ = syscall.Munmap(c.offHeapData)
			c.offHeapData = nil
		}
		c.origConn = nil
	})
	return c.closeErr
}

func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}

// wrapRealityClientConn wraps *utls.UConn and moves its embedded *utls.Conn to an off-heap mmap allocation.
// Under Go's race detector (-d=checkptr enabled by -race), sing-vmess/vless.NewVisionConn inspects
// the TLS connection using reflection and performs pointer arithmetic:
// unsafe.Pointer(reflectPointer + input.Offset) where reflectPointer is a uintptr.
// Because uintptr conversion strips the GC pointer tracking metadata, checkptr flags any pointer
// arithmetic derived from heap-allocated objects with:
// "fatal error: checkptr: pointer arithmetic result points to invalid allocation".
// Allocating *utls.Conn off-heap ensures checkptrBase returns 0, allowing checkptr to pass cleanly.
// origConn retains the heap reference preventing GC collection of internal cipher and buffer state.
func wrapRealityClientConn(uConn *utls.UConn) *realityClientConnWrapper {
	if uConn == nil || uConn.Conn == nil {
		return &realityClientConnWrapper{UConn: uConn}
	}
	size := int(unsafe.Sizeof(utls.Conn{}))
	pageSize := 4096
	if size > pageSize {
		pageSize = ((size + 4095) / 4096) * 4096
	}
	data, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return &realityClientConnWrapper{UConn: uConn}
	}
	// #nosec G103 -- off-heap mmap allocation required to bypass sing-vmess checkptr sanitizer false-positive
	connPtr := (*utls.Conn)(unsafe.Pointer(&data[0]))
	// #nosec G103 -- byte copy across off-heap allocation boundary
	copy(unsafe.Slice((*byte)(unsafe.Pointer(connPtr)), size), unsafe.Slice((*byte)(unsafe.Pointer(uConn.Conn)), size))
	origConn := uConn.Conn
	uConn.Conn = connPtr
	if uConn.HandshakeState.C != nil {
		uConn.HandshakeState.C = connPtr
	}
	w := &realityClientConnWrapper{
		UConn:       uConn,
		origConn:    origConn,
		offHeapData: data,
	}
	runtime.SetFinalizer(w, func(wrapper *realityClientConnWrapper) {
		_ = wrapper.Close()
	})
	return w
}

func parseClientHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox", "firefox_auto", "firefox_120":
		return utls.HelloFirefox_Auto
	case "safari", "safari_auto", "safari_16_0":
		return utls.HelloSafari_Auto
	case "ios", "ios_auto", "ios_14":
		return utls.HelloIOS_Auto
	case "edge", "edge_auto", "edge_85":
		return utls.HelloEdge_Auto
	case "random", "randomized":
		return utls.HelloRandomized
	case "360", "hello_360":
		return utls.Hello360_Auto
	case "qq", "hello_qq":
		return utls.HelloQQ_Auto
	case "android", "android_auto":
		return utls.HelloAndroid_11_OkHttp
	default:
		return utls.HelloChrome_Auto
	}
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
	var shortIDBytes [8]byte
	if len(p.ShortID) > 0 {
		decodedLen, err := hex.Decode(shortIDBytes[:], []byte(p.ShortID))
		if err != nil || decodedLen > 8 {
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

	switch p.Flow {
	case "", "xtls-rprx-vision":
	default:
		return nil, fmt.Errorf("vless: unsupported flow: %s", p.Flow)
	}

	fp := p.Fingerprint
	if fp == "" {
		fp = "chrome"
	}

	vlessClient, err := vless.NewClient(parsedUUID.String(), p.Flow, logger.NOP())
	if err != nil {
		return nil, fmt.Errorf("vless: vless client: %w", err)
	}

	return &Dialer{
		endpoint:      endpoint,
		client:        vlessClient,
		nd:            net.Dialer{},
		serverName:    p.ServerName,
		fingerprint:   fp,
		realityPubKey: pubKeyBytes,
		shortID:       shortIDBytes,
		engineProfile: strings.ToLower(strings.TrimSpace(p.EngineProfile)),
	}, nil
}

func (d *Dialer) isModernPQ() bool {
	switch d.engineProfile {
	case "modern_pq", "modern", "pq", "26.10.29", "v26.10.29", "modern pq", "post_quantum", "post-quantum":
		return true
	default:
		return false
	}
}

// configureKeyShares validates and adapts the ClientHello key shares to match the engine profile.
// When modern_pq is active and the requested fingerprint does not advertise X25519MLKEM768 hybrid shares,
// the dialer explicitly falls back to HelloChrome_Auto (which generates valid X25519MLKEM768 key shares),
// logging the substitution clearly to make the fallback explicit to operators.
func (d *Dialer) configureKeyShares(uConn *utls.UConn, uConfig *utls.Config, raw net.Conn) (*utls.UConn, error) {
	if d.isModernPQ() {
		hasPQShare := false
		for _, ext := range uConn.Extensions {
			if ks, ok := ext.(*utls.KeyShareExtension); ok {
				for _, share := range ks.KeyShares {
					if share.Group == utls.X25519MLKEM768 {
						hasPQShare = true
						break
					}
				}
			}
		}
		if !hasPQShare {
			slog.Info("vless: modern_pq requested but fingerprint lacks hybrid post-quantum key share, falling back to HelloChrome_Auto",
				"requested_fingerprint", d.fingerprint,
				"fallback_fingerprint", "HelloChrome_Auto",
			)
			uConn = utls.UClient(raw, uConfig, utls.HelloChrome_Auto)
			if err := uConn.BuildHandshakeState(); err != nil {
				return nil, fmt.Errorf("vless: build hybrid handshake state: %w", err)
			}
		}
		return uConn, nil
	}

	hasPQ := false
	for _, ext := range uConn.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			var filtered []utls.KeyShare
			for _, s := range ks.KeyShares {
				if s.Group == utls.X25519MLKEM768 || s.Group == utls.X25519Kyber768Draft00 {
					hasPQ = true
				} else {
					filtered = append(filtered, s)
				}
			}
			ks.KeyShares = filtered
		}
		if sc, ok := ext.(*utls.SupportedCurvesExtension); ok {
			var filtered []utls.CurveID
			for _, crv := range sc.Curves {
				if crv == utls.X25519MLKEM768 || crv == utls.X25519Kyber768Draft00 {
					hasPQ = true
				} else {
					filtered = append(filtered, crv)
				}
			}
			sc.Curves = filtered
		}
	}
	if hasPQ {
		if err := uConn.MarshalClientHello(); err != nil {
			return nil, fmt.Errorf("vless: marshal classical client hello: %w", err)
		}
	}
	return uConn, nil
}

func (d *Dialer) deriveAuthKey(keys *utls.KeySharePrivateKeys) ([]byte, error) {
	if keys == nil {
		return nil, errors.New("vless: nil KeyShareKeys")
	}
	var ecdheKey *ecdh.PrivateKey
	if keys.Ecdhe != nil {
		ecdheKey = keys.Ecdhe
	} else if keys.MlkemEcdhe != nil {
		ecdheKey = keys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, errors.New("vless: nil ecdheKey")
	}

	serverPubKey, err := ecdh.X25519().NewPublicKey(d.realityPubKey)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid server reality public key: %w", err)
	}

	authKey, err := ecdheKey.ECDH(serverPubKey)
	if err != nil || authKey == nil {
		return nil, fmt.Errorf("vless: ecdh key exchange: %w", err)
	}
	return authKey, nil
}

func (d *Dialer) sealRealityHello(hello *utls.PubClientHelloMsg, authKey []byte) ([]byte, error) {
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	nowTime := time.Now()
	nowSec := nowTime.Unix()
	if nowSec < 0 {
		nowSec = 0
	}
	// #nosec G115 -- unix timestamp is validated non-negative
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowSec))
	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	// #nosec G115 -- REALITY protocol mandates 32-bit big-endian timestamp field
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(uint64(nowSec)&0xFFFFFFFF))
	copy(hello.SessionId[8:], d.shortID[:])

	hkdfReader := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY"))
	derivedAuthKey := make([]byte, len(authKey))
	if _, err := io.ReadFull(hkdfReader, derivedAuthKey); err != nil {
		return nil, fmt.Errorf("vless: hkdf derive auth key: %w", err)
	}

	aesBlock, err := aes.NewCipher(derivedAuthKey)
	if err != nil {
		return nil, fmt.Errorf("vless: aes cipher: %w", err)
	}
	aesGcmCipher, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("vless: aes-gcm cipher: %w", err)
	}
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	return derivedAuthKey, nil
}

// handshake connects to the endpoint and executes the REALITY TLS handshake using metacubex/utls,
// sending both X25519MLKEM768 and X25519 key shares for modern_pq, or classical X25519 for legacy backends.
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

	helloID := parseClientHelloID(d.fingerprint)
	verifier := &realityVerifier{
		serverName: d.serverName,
	}

	uConfig := &utls.Config{
		ServerName:             d.serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifier.VerifyPeerCertificate,
		NextProtos:             []string{"h2", "http/1.1"},
	}

	uConn := utls.UClient(raw, uConfig, helloID)
	if err := uConn.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, 0, fmt.Errorf("vless: build handshake state: %w", err)
	}

	uConn, err = d.configureKeyShares(uConn, uConfig, raw)
	if err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	verifier.uConn = uConn

	for _, extension := range uConn.Extensions {
		if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
			alpnExtension.AlpnProtocols = []string{"h2", "http/1.1"}
			break
		}
	}

	authKey, err := d.deriveAuthKey(uConn.HandshakeState.State13.KeyShareKeys)
	if err != nil {
		_ = raw.Close()
		return nil, 0, err
	}

	derivedAuthKey, err := d.sealRealityHello(uConn.HandshakeState.Hello, authKey)
	if err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	verifier.authKey = derivedAuthKey

	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, 0, fmt.Errorf("vless: reality handshake: %w", err)
	}

	if !verifier.verified {
		_ = uConn.Close()
		return nil, 0, errors.New("vless: reality verification failed")
	}

	return wrapRealityClientConn(uConn), time.Since(start), nil
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
