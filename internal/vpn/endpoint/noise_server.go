package endpoint

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Server-role implementation of the AmneziaWG Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
// handshake accept path. It is the exact mirror of the client-role reference in
// internal/manager/awg/health/noise.go (BuildAWGInitiationPacket /
// VerifyAWGResponsePacket): those client functions are the wire-compatibility
// oracle for ParseInitiation/BuildResponse here, proven by
// TestServerRoleHandshakeRoundTrip.
//
// Handshake initiation wire layout (after the S1 junk prefix):
//
//	[ msg_type(4 LE = H1) ][ sender_idx(4 LE) ][ client_e_pub(32) ]
//	[ encrypted_static(48) ][ encrypted_timestamp(28) ][ MAC1(16) ][ MAC2(16) ]
//
// Handshake response wire layout (after the S2 junk prefix):
//
//	[ msg_type(4 LE = H2) ][ sender_idx(4 LE) ][ receiver_idx(4 LE) ]
//	[ server_e_pub(32) ][ encrypted_empty(16) ][ MAC1(16) ][ MAC2(16) ]

const (
	// initiationBodyLen is the size of an initiation message body:
	// 4 msg_type + 4 sender index + 32 client ephemeral pub
	// + 48 encrypted static + 28 encrypted timestamp.
	initiationBodyLen = 116
	// initiationWireLen is the full on-wire length after the S1 junk prefix:
	// body + 16-byte MAC1 + 16-byte MAC2.
	initiationWireLen = 148
	// responseBodyLen is the size of a handshake response message body:
	// 4 msg_type + 4 sender index + 4 receiver index + 32 server ephemeral pub
	// + 16 encrypted empty payload.
	responseBodyLen = 60
	// timestampWindowSeconds is the allowed clock drift for the anti-replay
	// TAI64N timestamp carried in the initiation.
	timestampWindowSeconds = 300
)

// Handshake accept-path errors. They are deliberately distinct so Batch 2 can
// classify datagrams that are not initiations (transport data for established
// sessions) from cryptographic rejections.
var (
	// ErrDatagramTooShort means the datagram cannot even hold a junk prefix
	// plus a full initiation message.
	ErrDatagramTooShort = errors.New("datagram too short for AWG handshake initiation")
	// ErrNotInitiation means the message type field does not match H1.
	ErrNotInitiation = errors.New("message type is not an AWG handshake initiation")
	// ErrMAC1Failed means the unencrypted MAC1 tag did not verify against the
	// server public key (wrong server key, tampered body, or garbage).
	ErrMAC1Failed = errors.New("initiation MAC1 verification failed")
	// ErrDecryptStatic means the encrypted client static key failed AEAD
	// decryption (wrong server key or tampered ciphertext after a valid MAC1).
	ErrDecryptStatic = errors.New("failed to decrypt client static key (wrong server key or tampered packet)")
	// ErrDecryptTimestamp means the encrypted TAI64N timestamp failed AEAD
	// decryption (tampered ciphertext after a valid MAC1).
	ErrDecryptTimestamp = errors.New("failed to decrypt initiation timestamp")
	// ErrTimestampStale means the initiation timestamp is outside the
	// anti-replay window.
	ErrTimestampStale = errors.New("initiation timestamp outside anti-replay window")
	// ErrInvalidHandshakeState means BuildResponse was called with a nil or
	// incomplete InitiationInfo.
	ErrInvalidHandshakeState = errors.New("invalid or incomplete handshake state")
)

// InitiationInfo carries the verified state of a parsed AWG handshake
// initiation: the peer's static and ephemeral public keys, the peer's chosen
// session index, and the Noise hash and chaining key needed to build the
// matching handshake response.
type InitiationInfo struct {
	// ClientStaticPub is the decrypted client static public key. Its base64
	// form is the peer identity matched against user_connections
	// (models.UserConnection.ClientID) by the DBAuthenticator.
	ClientStaticPub []byte
	// ClientEPub is the client's ephemeral handshake public key.
	ClientEPub []byte
	// SenderIndex is the client-chosen session index echoed back in the
	// response receiver index field.
	SenderIndex uint32
	// H is the Noise hash after mixing the full initiation message.
	H []byte
	// CK is the Noise chaining key after processing the initiation message.
	CK []byte
	// TimestampUnix is the decrypted TAI64N timestamp in Unix seconds.
	TimestampUnix int64
}

// TransportKeys holds the final Noise transport keys derived after a
// successful handshake. The server is the Noise responder: SendKey encrypts
// server-to-client traffic and RecvKey decrypts client-to-server traffic
// (WireGuard tempK2/tempK1 responder assignment from KDF2(ck, empty)).
// Data-plane use of these keys is Batch 2 scope.
type TransportKeys struct {
	SendKey []byte
	RecvKey []byte
}

// concat joins two byte slices into a freshly allocated result. It never
// appends into shared package-level slices such as health.LabelMAC1.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// mixHash computes BLAKE2s-256 over the concatenation of a and b, mirroring
// the hash mixing steps of the client-role reference implementation.
func mixHash(a, b []byte) []byte {
	sum := blake2s.Sum256(concat(a, b))
	return sum[:]
}

// nonceZero is the all-zero 12-byte ChaCha20-Poly1305 nonce used by every
// Noise message seal/open in this handshake (single nonce per key).
func nonceZero() []byte {
	return make([]byte, chacha20poly1305.NonceSize)
}

// ParseInitiation parses and verifies an AmneziaWG handshake initiation
// datagram received by the server role. serverPriv is the endpoint's Noise
// server private key (see ServerKeysManager); h1 and s1 are the AWG message
// type and junk prefix length the endpoint is configured with (zero/negative
// select the health package defaults). On success it returns the decrypted
// peer identity and the Noise hash/chain-key state needed to build the
// response.
func ParseInitiation(serverPriv []byte, datagram []byte, h1 uint32, s1 int) (*InitiationInfo, error) {
	if len(serverPriv) != 32 {
		return nil, errors.New("server private key must be 32 bytes")
	}
	if h1 == 0 {
		h1 = health.DefaultH1
	}
	if s1 < 0 {
		s1 = health.DefaultS1
	}
	if len(datagram) < s1+initiationWireLen {
		return nil, ErrDatagramTooShort
	}

	payload := datagram[s1:]
	msgType := binary.LittleEndian.Uint32(payload[0:4])
	if msgType != h1 {
		return nil, ErrNotInitiation
	}
	senderIdx := binary.LittleEndian.Uint32(payload[4:8])

	clientEPub := make([]byte, 32)
	copy(clientEPub, payload[8:40])
	encStatic := payload[40:88]
	encTS := payload[88:116]
	receivedMAC1 := payload[116:132]

	// MAC1 is keyed with the SERVER's public key (mirror of the client-side
	// derivation in BuildAWGInitiationPacket) and covers the unencrypted body.
	serverPub, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive server public key: %w", err)
	}
	mac1KeySum := blake2s.Sum256(concat(health.LabelMAC1, serverPub))
	mac1Hasher, err := blake2s.New128(mac1KeySum[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create MAC1 hasher: %w", err)
	}
	mac1Hasher.Write(payload[:initiationBodyLen])
	if !hmac.Equal(mac1Hasher.Sum(nil), receivedMAC1) {
		return nil, ErrMAC1Failed
	}

	// Noise chain, mirroring client steps 1-7 of BuildAWGInitiationPacket.
	h := mixHash(health.InitialHash[:], serverPub)
	h = mixHash(h, clientEPub)
	ck := health.KDF1(health.InitialChainKey[:], clientEPub)

	// ss1 = DH(server_priv, client_e_pub) == client's DH(client_e_priv, server_pub).
	ss1, err := curve25519.X25519(serverPriv, clientEPub)
	if err != nil {
		return nil, fmt.Errorf("first DH exchange failed: %w", err)
	}
	ck, key1 := health.KDF2(ck, ss1)

	aead1, err := chacha20poly1305.New(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead1: %w", err)
	}
	clientStatic, err := aead1.Open(nil, nonceZero(), encStatic, h)
	if err != nil {
		return nil, ErrDecryptStatic
	}
	if len(clientStatic) != 32 {
		return nil, ErrDecryptStatic
	}
	h = mixHash(h, encStatic)

	// ss2 = DH(server_priv, client_static_pub) == client's DH(client_priv, server_pub).
	ss2, err := curve25519.X25519(serverPriv, clientStatic)
	if err != nil {
		return nil, fmt.Errorf("second DH exchange failed: %w", err)
	}
	ck, key2 := health.KDF2(ck, ss2)

	aead2, err := chacha20poly1305.New(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead2: %w", err)
	}
	tai64n, err := aead2.Open(nil, nonceZero(), encTS, h)
	if err != nil {
		return nil, ErrDecryptTimestamp
	}
	if len(tai64n) < 12 {
		return nil, ErrDecryptTimestamp
	}
	h = mixHash(h, encTS)

	// Anti-replay: reject initiations whose TAI64N timestamp drifts more than
	// timestampWindowSeconds from the server clock.
	// #nosec G115 -- TAI64N epoch offset conversion; wraparound is the
	// intended two's-complement encoding of pre-1970 timestamps.
	unixSec := int64(binary.BigEndian.Uint64(tai64n[0:8]) - 0x400000000000000A)
	drift := time.Now().Unix() - unixSec
	if drift > timestampWindowSeconds || drift < -timestampWindowSeconds {
		return nil, ErrTimestampStale
	}

	return &InitiationInfo{
		ClientStaticPub: clientStatic,
		ClientEPub:      clientEPub,
		SenderIndex:     senderIdx,
		H:               h,
		CK:              ck,
		TimestampUnix:   unixSec,
	}, nil
}

// BuildResponse builds the AmneziaWG handshake response for a previously
// parsed initiation and derives the session transport keys. The response
// verifies against health.VerifyAWGResponsePacket on the client side; that
// verifier derives its keys from the same two DH values by X25519 symmetry
// (server: DH(server_e_priv, client_e_pub) / DH(server_e_priv, client_static),
// client: DH(client_e_priv, server_e_pub) / DH(client_priv, server_e_pub)),
// so the h/ck mixing order here must stay the exact mirror of the client.
//
// PSK policy: panel client registrations do not carry a preshared key, so the
// Noise IKpsk2 preshared key is 32 zero bytes on both sides — matching
// BuildAWGInitiationPacket's psk==nil handling and the client state it stores.
func BuildResponse(serverPriv []byte, info *InitiationInfo, h2 uint32, s2 int) (resp []byte, sessionKeys *TransportKeys, err error) {
	if info == nil {
		return nil, nil, ErrInvalidHandshakeState
	}
	if len(info.H) != 32 || len(info.CK) != 32 {
		return nil, nil, ErrInvalidHandshakeState
	}
	if len(info.ClientStaticPub) != 32 || len(info.ClientEPub) != 32 {
		return nil, nil, ErrInvalidHandshakeState
	}
	if h2 == 0 {
		h2 = health.DefaultH2
	}
	if s2 < 0 {
		s2 = health.DefaultS2
	}

	// Server ephemeral keypair.
	serverEPriv := make([]byte, 32)
	if _, err := rand.Read(serverEPriv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate server ephemeral key: %w", err)
	}
	serverEPub, err := curve25519.X25519(serverEPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute server ephemeral public key: %w", err)
	}

	// Noise chain continuation (mirror of VerifyAWGResponsePacket).
	h := mixHash(info.H, serverEPub)
	ck := health.KDF1(info.CK, serverEPub)

	ss3, err := curve25519.X25519(serverEPriv, info.ClientEPub)
	if err != nil {
		return nil, nil, fmt.Errorf("first response DH exchange failed: %w", err)
	}
	ck = health.KDF1(ck, ss3)

	ss4, err := curve25519.X25519(serverEPriv, info.ClientStaticPub)
	if err != nil {
		return nil, nil, fmt.Errorf("second response DH exchange failed: %w", err)
	}
	ck = health.KDF1(ck, ss4)

	// No-PSK policy: 32 zero bytes (see function godoc).
	psk := make([]byte, 32)
	ck, tau, key3 := health.KDF3(ck, psk)
	h = mixHash(h, tau)

	aead3, err := chacha20poly1305.New(key3)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aead3: %w", err)
	}
	encryptedEmpty := aead3.Seal(nil, nonceZero(), nil, h)
	if len(encryptedEmpty) != 16 {
		return nil, nil, fmt.Errorf("unexpected encrypted empty payload length: %d", len(encryptedEmpty))
	}

	// Final transport keys. Server is the responder: it sends with tempK2 and
	// receives with tempK1.
	recvKey, sendKey := health.KDF2(ck, nil)
	transportKeys := &TransportKeys{SendKey: sendKey, RecvKey: recvKey}

	// Assemble the 60-byte response body.
	var idxBuf [4]byte
	var serverIdxBuf [4]byte
	if _, err := rand.Read(serverIdxBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate server session index: %w", err)
	}

	body := make([]byte, 0, responseBodyLen)
	binary.LittleEndian.PutUint32(idxBuf[:], h2)
	body = append(body, idxBuf[:]...)
	// sender index: the 4 random bytes are already a little-endian uint32 on
	// the wire by construction.
	body = append(body, serverIdxBuf[:]...)
	binary.LittleEndian.PutUint32(idxBuf[:], info.SenderIndex)
	body = append(body, idxBuf[:]...) // receiver index: echo client's sender index
	body = append(body, serverEPub...)
	body = append(body, encryptedEmpty...)
	if len(body) != responseBodyLen {
		return nil, nil, fmt.Errorf("internal error: response body length %d, want %d", len(body), responseBodyLen)
	}

	// MAC1 is keyed with the CLIENT's static public key (the server's view of
	// the peer); MAC2 is 16 zero bytes (no cookie support).
	mac1KeySum := blake2s.Sum256(concat(health.LabelMAC1, info.ClientStaticPub))
	mac1Hasher, err := blake2s.New128(mac1KeySum[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create response MAC1 hasher: %w", err)
	}
	mac1Hasher.Write(body)
	mac1 := mac1Hasher.Sum(nil)

	resp = make([]byte, 0, s2+len(body)+32)
	if s2 > 0 {
		junk := make([]byte, s2)
		if _, err := rand.Read(junk); err != nil {
			return nil, nil, fmt.Errorf("failed to generate S2 padding: %w", err)
		}
		resp = append(resp, junk...)
	}
	resp = append(resp, body...)
	resp = append(resp, mac1...)
	resp = append(resp, make([]byte, 16)...) // MAC2

	return resp, transportKeys, nil
}
