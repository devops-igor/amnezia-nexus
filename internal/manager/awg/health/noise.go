package health

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

var (
	InitialChainKey = blake2s.Sum256([]byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"))
	InitialHash     = blake2s.Sum256(append(InitialChainKey[:], []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")...))
	LabelMAC1       = []byte("mac1----")
)

const (
	DefaultH1 = uint32(1020325451)
	DefaultH2 = uint32(3288052141)
	DefaultH3 = uint32(1766607858)
	DefaultH4 = uint32(2528465083)
	DefaultS1 = 15
	DefaultS2 = 18
	DefaultS3 = 20
	DefaultS4 = 23

	// MessageInitiationSize is the full AWG handshake initiation message size
	// (116-byte body + 16-byte MAC1 + 16-byte MAC2).
	MessageInitiationSize = 148
	// MessageResponseSize is the full AWG handshake response message size
	// (60-byte body + 16-byte MAC1 + 16-byte MAC2).
	MessageResponseSize = 92
)

// HeaderCipherNonceSize is the nonce length used by the header protection cipher.
const HeaderCipherNonceSize = 12

// NewHeaderProtectionCipher builds the unauthenticated ChaCha20 header protection
// cipher (mirrors upstream HeaderProtectionCipher: chacha20.NewUnauthenticatedCipher
// with the 32-byte HP key and a 12-byte salt). Returns nil when the HP key is unset.
func NewHeaderProtectionCipher(hpKey, salt []byte) cipher.Stream {
	if len(hpKey) != 32 {
		return nil
	}
	if len(salt) < HeaderCipherNonceSize {
		return nil
	}
	c, err := chacha20.NewUnauthenticatedCipher(hpKey[:32], salt[:HeaderCipherNonceSize])
	if err != nil {
		return nil
	}
	return c
}

// newHeaderProtectionCipher is an internal alias for NewHeaderProtectionCipher.
func newHeaderProtectionCipher(hpKey, salt []byte) cipher.Stream {
	return NewHeaderProtectionCipher(hpKey, salt)
}

// NoiseClientState maintains state across Noise protocol handshake messages.
type NoiseClientState struct {
	H           []byte
	CK          []byte
	ClientEPriv []byte
	ClientPriv  []byte
	ServerPub   []byte
	PSK         []byte
	SenderIndex uint32
	MAC1Key     []byte
}

// HMACBlake2s computes standard HMAC-BLAKE2s-256 for Noise KDF functions.
func HMACBlake2s(key, data []byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// KDF1 derives a new chaining key from key and input data.
func KDF1(key, data []byte) []byte {
	prk := HMACBlake2s(key, data)
	return HMACBlake2s(prk, []byte{0x01})
}

// KDF2 derives a new chaining key and an encryption key.
func KDF2(key, data []byte) (t1, t2 []byte) {
	prk := HMACBlake2s(key, data)
	t1 = HMACBlake2s(prk, []byte{0x01})
	t2 = HMACBlake2s(prk, append(t1, 0x02))
	return t1, t2
}

// KDF3 derives a new chaining key, a tau hash, and an encryption key.
func KDF3(key, data []byte) (t1, t2, t3 []byte) {
	prk := HMACBlake2s(key, data)
	t1 = HMACBlake2s(prk, []byte{0x01})
	t2 = HMACBlake2s(prk, append(t1, 0x02))
	t3 = HMACBlake2s(prk, append(t2, 0x03))
	return t1, t2, t3
}

// DecodeKey decodes base64 or hex string or returns 32 raw key bytes.
func DecodeKey(keyVal any) ([]byte, error) {
	switch v := keyVal.(type) {
	case []byte:
		if len(v) == 32 {
			return v, nil
		}
		return nil, fmt.Errorf("byte key must be 32 bytes, got %d", len(v))
	case string:
		v = strings.TrimSpace(v)
		// If 64 hex characters, try hex decoding first.
		if len(v) == 64 {
			if decoded, err := hex.DecodeString(v); err == nil && len(decoded) == 32 {
				return decoded, nil
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		if decodedHex, errHex := hex.DecodeString(v); errHex == nil && len(decodedHex) == 32 {
			return decodedHex, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 or hex key: %w", err)
		}
		return nil, fmt.Errorf("decoded base64 key must be 32 bytes, got %d", len(decoded))
	default:
		return nil, errors.New("unsupported key type")
	}
}

// BuildAWGInitiationPacket creates an AmneziaWG Handshake Initiation packet and state.
func BuildAWGInitiationPacket(serverPubKey, clientPrivKey, psk []byte, h1 any, s1 int) ([]byte, *NoiseClientState, error) {
	if len(serverPubKey) != 32 {
		return nil, nil, errors.New("server public key must be 32 bytes")
	}

	if clientPrivKey == nil {
		clientPrivKey = make([]byte, 32)
		if _, err := rand.Read(clientPrivKey); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random client private key: %w", err)
		}
	} else if len(clientPrivKey) != 32 {
		return nil, nil, errors.New("client private key must be 32 bytes")
	}

	clientPubKey, err := curve25519.X25519(clientPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute client public key: %w", err)
	}

	if psk == nil {
		psk = make([]byte, 32)
	} else if len(psk) != 32 {
		return nil, nil, errors.New("psk must be 32 bytes")
	}

	h1Range, err := models.ParseHeaderRange(h1)
	if err != nil || h1Range.IsZero() {
		h1Range = models.DegenerateHeaderRange(DefaultH1)
	}
	h1Val := h1Range.PickOne()

	if s1 < 0 {
		s1 = DefaultS1
	}

	// 1. Initialize Noise hash & chain key
	hSum := blake2s.Sum256(append(InitialHash[:], serverPubKey...))
	h := hSum[:]
	ck := InitialChainKey[:]

	// 2. Generate client ephemeral keypair
	clientEPriv := make([]byte, 32)
	if _, err := rand.Read(clientEPriv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}
	clientEPub, err := curve25519.X25519(clientEPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute ephemeral public key: %w", err)
	}

	// 3. Mix ephemeral public key into hash & chain key
	hSum = blake2s.Sum256(append(h, clientEPub...))
	h = hSum[:]
	ck = KDF1(ck, clientEPub)

	// 4. First DH exchange: ss1 = DH(client_e_priv, serverPubKey)
	ss1, err := curve25519.X25519(clientEPriv, serverPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("first DH exchange failed: %w", err)
	}
	var key1 []byte
	ck, key1 = KDF2(ck, ss1)

	// 5. Encrypt client static public key with key1
	aead1, err := chacha20poly1305.New(key1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aead1: %w", err)
	}
	nonce0 := make([]byte, 12)
	encryptedStatic := aead1.Seal(nil, nonce0, clientPubKey, h)
	hSum = blake2s.Sum256(append(h, encryptedStatic...))
	h = hSum[:]

	// 6. Second DH exchange: ss2 = DH(clientPrivKey, serverPubKey)
	ss2, err := curve25519.X25519(clientPrivKey, serverPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("second DH exchange failed: %w", err)
	}
	var key2 []byte
	ck, key2 = KDF2(ck, ss2)

	// 7. Generate and encrypt TAI64N timestamp
	now := time.Now()
	unixSec := now.Unix()
	unixNsec := now.Nanosecond()
	// #nosec G115
	taiSec := uint64(0x400000000000000A + unixSec)
	// #nosec G115
	taiNsec := uint32(unixNsec & ^0xFFFFFF)

	tai64n := make([]byte, 12)
	binary.BigEndian.PutUint64(tai64n[0:8], taiSec)
	binary.BigEndian.PutUint32(tai64n[8:12], taiNsec)

	aead2, err := chacha20poly1305.New(key2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aead2: %w", err)
	}
	encryptedTimestamp := aead2.Seal(nil, nonce0, tai64n, h)
	hSum = blake2s.Sum256(append(h, encryptedTimestamp...))
	h = hSum[:]

	// 8. Assemble 116-byte message body
	idxBig, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate sender index: %w", err)
	}
	// #nosec G115
	senderIdx := uint32(idxBig.Int64())

	msgTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgTypeBytes, h1Val)

	senderIdxBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(senderIdxBytes, senderIdx)

	var msgBody []byte
	msgBody = append(msgBody, msgTypeBytes...)
	msgBody = append(msgBody, senderIdxBytes...)
	msgBody = append(msgBody, clientEPub...)
	msgBody = append(msgBody, encryptedStatic...)
	msgBody = append(msgBody, encryptedTimestamp...)

	// 9. Compute MAC1 (16 bytes) and MAC2 (16 zero bytes)
	mac1KeySum := blake2s.Sum256(append(LabelMAC1, serverPubKey...))
	mac1Key := mac1KeySum[:]
	hMac1, err := blake2s.New128(mac1Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create mac1 hasher: %w", err)
	}
	hMac1.Write(msgBody)
	mac1 := hMac1.Sum(nil)
	mac2 := make([]byte, 16)

	// 10. Frame wire packet with S1 random junk bytes at the front
	var packet []byte
	if s1 > 0 {
		padding := make([]byte, s1)
		if _, err := rand.Read(padding); err != nil {
			return nil, nil, fmt.Errorf("failed to generate S1 padding: %w", err)
		}
		packet = append(packet, padding...)
	}
	packet = append(packet, msgBody...)
	packet = append(packet, mac1...)
	packet = append(packet, mac2...)

	state := &NoiseClientState{
		H:           h,
		CK:          ck,
		ClientEPriv: clientEPriv,
		ClientPriv:  clientPrivKey,
		ServerPub:   serverPubKey,
		PSK:         psk,
		SenderIndex: senderIdx,
		MAC1Key:     mac1Key,
	}

	return packet, state, nil
}

// BuildAWGInitiationPacketObfuscated builds an AmneziaWG Handshake Initiation packet
// with header protection applied. The MAC1/MAC2 tags are computed over the plaintext
// message body BEFORE obfuscation (upstream order: AddMacs then header protection).
// The HP keystream is message-relative: it is seeded with the first
// HeaderCipherNonceSize bytes of the packet (the junk prefix) but XORed starting at
// keystream offset 0 onto packet[s1:s1+MessageInitiationSize]; any random trailer
// beyond the message stays plaintext.
func BuildAWGInitiationPacketObfuscated(serverPubKey, clientPrivKey, psk, hpKey []byte, h1 any, s1 int) ([]byte, *NoiseClientState, error) {
	if len(hpKey) != 32 {
		return nil, nil, errors.New("header protection key must be 32 bytes")
	}
	// Header protection requires every junk section to be >= HeaderCipherNonceSize
	// (upstream uapi hard constraint) so the 12-byte nonce prefix cannot overlap
	// the message body.
	if s1 < HeaderCipherNonceSize {
		s1 = HeaderCipherNonceSize
	}

	packet, state, err := BuildAWGInitiationPacket(serverPubKey, clientPrivKey, psk, h1, s1)
	if err != nil {
		return nil, nil, err
	}

	cip := newHeaderProtectionCipher(hpKey, packet)
	if cip == nil {
		return nil, nil, errors.New("failed to create header protection cipher")
	}
	end := s1 + MessageInitiationSize
	cip.XORKeyStream(packet[s1:end], packet[s1:end])

	return packet, state, nil
}

// VerifyAWGResponsePacketObfuscated verifies a header-protected AmneziaWG Handshake
// Response packet. It copies the raw datagram (preserving junk-prefix positions),
// de-obfuscates resp[s2:s2+MessageResponseSize] with the keystream seeded from the
// first HeaderCipherNonceSize bytes of the packet (message-relative alignment,
// keystream offset 0 == message offset 0), then delegates to VerifyAWGResponsePacket.
func VerifyAWGResponsePacketObfuscated(respPacket []byte, state *NoiseClientState, hpKey []byte, h2 any, s2 int) bool {
	if state == nil || len(hpKey) != 32 {
		return false
	}
	// Mirror the initiator-side constraint: junk sections must be at least as
	// long as the nonce so the keystream never overlaps the message.
	if s2 < HeaderCipherNonceSize {
		s2 = HeaderCipherNonceSize
	}
	if len(respPacket) < s2+MessageResponseSize {
		return false
	}

	cip := newHeaderProtectionCipher(hpKey, respPacket)
	if cip == nil {
		return false
	}
	buf := make([]byte, len(respPacket))
	copy(buf, respPacket)
	end := s2 + MessageResponseSize
	cip.XORKeyStream(buf[s2:end], buf[s2:end])

	return VerifyAWGResponsePacket(buf, state, h2, s2)
}

// ComputePublicKeyFromPrivate computes the base64-encoded WireGuard/AmneziaWG public key from a base64-encoded private key.
func ComputePublicKeyFromPrivate(clientPrivKey string) (string, error) {
	privBytes, err := DecodeKey(clientPrivKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", errors.New("client private key must be 32 bytes")
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to compute public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

// VerifyAWGResponsePacket verifies and authenticates an AmneziaWG Handshake Response packet.
func VerifyAWGResponsePacket(respPacket []byte, state *NoiseClientState, h2 any, s2 int) bool {
	if state == nil {
		return false
	}
	h2Range, err := models.ParseHeaderRange(h2)
	if err != nil || h2Range.IsZero() {
		h2Range = models.DegenerateHeaderRange(DefaultH2)
	}
	if s2 < 0 {
		s2 = DefaultS2
	}

	expectedMinLen := s2 + 92
	if len(respPacket) < expectedMinLen {
		return false
	}

	payload := respPacket[s2:]
	msgType := binary.LittleEndian.Uint32(payload[0:4])
	if !h2Range.Contains(msgType) && msgType != 2 {
		return false
	}

	receiverIdx := binary.LittleEndian.Uint32(payload[8:12])
	if receiverIdx != state.SenderIndex {
		return false
	}

	// Verify MAC1 over payload[0:60] using state.MAC1Key (blake2s hash with LabelMAC1 and client static pub key)
	var mac1Key []byte
	if len(state.ClientPriv) == 32 {
		if clientPub, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint); err == nil {
			k := blake2s.Sum256(append(LabelMAC1, clientPub...))
			mac1Key = k[:]
		}
	}
	if mac1Key == nil && len(state.MAC1Key) == 32 {
		mac1Key = state.MAC1Key
	}
	if len(mac1Key) == 32 {
		hMac1, err := blake2s.New128(mac1Key)
		if err != nil {
			return false
		}
		hMac1.Write(payload[0:60])
		if !hmac.Equal(payload[60:76], hMac1.Sum(nil)) {
			// If state.MAC1Key was explicitly provided and differs from derived key, check it as well
			if len(state.MAC1Key) == 32 && !bytes.Equal(state.MAC1Key, mac1Key) {
				hMac1Alt, err := blake2s.New128(state.MAC1Key)
				if err != nil {
					return false
				}
				hMac1Alt.Write(payload[0:60])
				if !hmac.Equal(payload[60:76], hMac1Alt.Sum(nil)) {
					return false
				}
			} else {
				return false
			}
		}
	} else {
		return false
	}

	serverEPub := payload[12:44]
	encryptedEmpty := payload[44:60]

	// Complete Noise handshake verification
	hSum := blake2s.Sum256(append(state.H, serverEPub...))
	h := hSum[:]
	ck := KDF1(state.CK, serverEPub)

	ss3, err := curve25519.X25519(state.ClientEPriv, serverEPub)
	if err != nil {
		return false
	}
	ck = KDF1(ck, ss3)

	ss4, err := curve25519.X25519(state.ClientPriv, serverEPub)
	if err != nil {
		return false
	}
	ck = KDF1(ck, ss4)

	var tau, key3 []byte
	_, tau, key3 = KDF3(ck, state.PSK)
	hSum = blake2s.Sum256(append(h, tau...))
	h = hSum[:]

	aead3, err := chacha20poly1305.New(key3)
	if err != nil {
		return false
	}
	nonce0 := make([]byte, 12)
	decrypted, err := aead3.Open(nil, nonce0, encryptedEmpty, h)
	if err != nil {
		return false
	}

	return len(decrypted) == 0
}
