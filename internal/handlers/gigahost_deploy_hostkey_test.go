package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestRework4HostKeyAlgorithms(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		public any
		valid  bool
	}{
		{"ecdsa", &ecdsaKey.PublicKey, true},
		{"rsa2048", &rsaKey.PublicKey, true},
		{"rsa1024", &weakRSA.PublicKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := gossh.NewPublicKey(tc.public)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSSHKeyInvariants(key); (err == nil) != tc.valid {
				t.Fatalf("key acceptance=%t, want %t", err == nil, tc.valid)
			}
		})
	}
}
