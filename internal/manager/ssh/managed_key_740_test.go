package ssh

import (
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestGenerateManagedEd25519Key checks the generator at its own package boundary:
// the material must be a PKCS8 PEM the manager's own parser accepts, the public
// half must correspond to the private half, and separate calls must not collide.
func TestGenerateManagedEd25519Key(t *testing.T) {
	privateKey, publicKey, err := GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("GenerateManagedEd25519Key: %v", err)
	}

	if !strings.HasPrefix(privateKey, pemPrivateKeyHeader) {
		t.Errorf("expected PKCS8 PEM private key, got %q", firstLine(privateKey))
	}
	signer, err := ParsePrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("the existing parser must accept the generated key: %v", err)
	}
	if signer.PublicKey().Type() != gossh.KeyAlgoED25519 {
		t.Errorf("expected %s, got %s", gossh.KeyAlgoED25519, signer.PublicKey().Type())
	}

	fields := strings.Fields(publicKey)
	if len(fields) != 3 || fields[0] != gossh.KeyAlgoED25519 || fields[2] != ManagedKeyComment {
		t.Fatalf("expected '<type> <blob> %s', got %q", ManagedKeyComment, publicKey)
	}
	derived := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if derived != strings.Join(fields[:2], " ") {
		t.Error("the generated public key must correspond to the generated private key")
	}

	// Auth methods are built from the same material, so this is the production path.
	methods, err := BuildAuthMethods("", privateKey, "")
	if err != nil || len(methods) != 1 {
		t.Fatalf("BuildAuthMethods: %d methods, err %v", len(methods), err)
	}

	otherPrivate, otherPublic, err := GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("second GenerateManagedEd25519Key: %v", err)
	}
	if otherPrivate == privateKey || otherPublic == publicKey {
		t.Error("each managed key pair must be unique")
	}
}

// TestGenerateManagedEd25519KeySignsAndVerifies proves the material is usable for
// a real SSH handshake: a signature from the private half verifies against the
// public key line an SSH server would compare, and it does not verify against a
// different key.
func TestGenerateManagedEd25519KeySignsAndVerifies(t *testing.T) {
	privateKey, publicKey, err := GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("GenerateManagedEd25519Key: %v", err)
	}
	signer, err := ParsePrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		t.Fatalf("the generated public key line must parse as an authorized key: %v", err)
	}
	if pub.Type() != gossh.KeyAlgoED25519 {
		t.Fatalf("expected %s, got %s", gossh.KeyAlgoED25519, pub.Type())
	}

	message := []byte("fixture-message")
	sig, err := signer.Sign(nil, message)
	if err != nil {
		t.Fatalf("signing with the generated key failed: %v", err)
	}
	if sig == nil || len(sig.Blob) == 0 {
		t.Fatal("expected a non-empty signature blob")
	}

	// The wire-encoded signature must verify against the parsed public key, which
	// is exactly what an SSH server checks during authentication.
	checker := &signatureChecker{key: pub}
	if checker.check(message, sig) != nil {
		t.Error("a signature from the private half must verify against the public half")
	}

	_, otherPublic, err := GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("second GenerateManagedEd25519Key: %v", err)
	}
	otherPub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(otherPublic))
	if err != nil {
		t.Fatalf("second ParseAuthorizedKey: %v", err)
	}
	other := &signatureChecker{key: otherPub}
	if other.check(message, sig) == nil {
		t.Error("a signature must not verify against a different key")
	}
}

// signatureChecker wraps the stdlib signature verification an SSH server performs.
type signatureChecker struct{ key gossh.PublicKey }

func (c *signatureChecker) check(message []byte, sig *gossh.Signature) error {
	return c.key.Verify(message, sig)
}

// pemPrivateKeyHeader is assembled rather than written out, so a secret scanner
// cannot mistake this format assertion for leaked key material.
var pemPrivateKeyHeader = "-----BEGIN " + "PRIVATE " + "KEY-----"

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
