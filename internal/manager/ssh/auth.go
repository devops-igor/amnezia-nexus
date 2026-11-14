package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

var (
	// ErrNoAuthMethod is returned when neither password nor private key is provided.
	ErrNoAuthMethod = errors.New("no authentication method provided: specify password or private_key")
	// ErrEmptyPrivateKey is returned when private key data is empty.
	ErrEmptyPrivateKey = errors.New("private key content is empty")
	// ErrInvalidPrivateKey is returned when the private key cannot be parsed.
	ErrInvalidPrivateKey = errors.New("invalid or unparseable private key")
	// ErrPassphraseRequired is returned when an encrypted key has no passphrase.
	ErrPassphraseRequired = errors.New("passphrase required for encrypted private key")
	// ErrInvalidPassphrase is returned when decrypting a private key with the wrong passphrase.
	ErrInvalidPassphrase = errors.New("failed to decrypt private key: invalid passphrase or corrupted key")
)

// BuildAuthMethods constructs SSH authentication methods from password and/or private key credentials.
func BuildAuthMethods(password, privateKeyPEM, passphrase string) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod

	trimmedKey := strings.TrimSpace(privateKeyPEM)
	if trimmedKey != "" {
		signer, err := ParsePrivateKey(trimmedKey, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}

	if password != "" {
		methods = append(methods, gossh.Password(password))
		methods = append(methods, gossh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			},
		))
	}

	if len(methods) == 0 {
		return nil, ErrNoAuthMethod
	}

	return methods, nil
}

// ParsePrivateKey parses a PEM-encoded private key (RSA, Ed25519, ECDSA) with optional passphrase.
func ParsePrivateKey(keyPEM, passphrase string) (gossh.Signer, error) {
	raw := []byte(strings.TrimSpace(keyPEM))
	if len(raw) == 0 {
		return nil, ErrEmptyPrivateKey
	}

	trimmedPass := strings.TrimSpace(passphrase)
	if trimmedPass != "" {
		signer, err := gossh.ParsePrivateKeyWithPassphrase(raw, []byte(trimmedPass))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPassphrase, err)
		}
		return signer, nil
	}

	signer, err := gossh.ParsePrivateKey(raw)
	if err != nil {
		var missingPassErr *gossh.PassphraseMissingError
		if errors.As(err, &missingPassErr) {
			return nil, ErrPassphraseRequired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	return signer, nil
}

// GenerateTestRSAKey generates an in-memory PEM-encoded RSA private key for testing.
func GenerateTestRSAKey(bits int) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateTestEd25519Key generates an in-memory PEM-encoded Ed25519 private key for testing.
func GenerateTestEd25519Key() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ManagedKeyComment is appended to managed public keys so an operator reading
// the provider account can tell which key material the panel generated.
const ManagedKeyComment = "nexus-managed"

// GenerateManagedEd25519Key creates the Ed25519 key pair used for a
// panel-managed deployment.
//
// It returns the private key as PKCS8 PEM (the encoding ParsePrivateKey already
// reads, so the existing SSH manager needs no new parser) and the public key as
// a single authorized_keys line ready for provider registration. The private
// material never leaves the caller: persistence encrypts it with the same
// credential encryption the server table uses.
func GenerateManagedEd25519Key() (privateKeyPEM, authorizedKey string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate managed ed25519 key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("derive managed ed25519 signer: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal managed ed25519 key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", "", fmt.Errorf("encode managed ed25519 key: %w", err)
	}

	publicLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if publicLine == "" {
		return "", "", errors.New("derive managed ed25519 public key: empty authorized key line")
	}
	return buf.String(), publicLine + " " + ManagedKeyComment, nil
}

// GenerateTestECDSAKey generates an in-memory PEM-encoded ECDSA P-256 private key for testing.
func GenerateTestECDSAKey() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}
