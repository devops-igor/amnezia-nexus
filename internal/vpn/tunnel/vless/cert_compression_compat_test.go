//go:build with_utls

package vless

// Compatibility qualification for the round22 dependency security follow-up
// (GO-2026-6888 brotli, GO-2026-6865 klauspost/compress).
//
// The security fix must not merely bump a version: the decompressors utls
// actually calls on the REALITY handshake path
// (metacubex/utls u_handshake_client.go:72 `brotli.NewReader`, :84
// `zstd.NewReader`) must still decode real payloads on the upgraded modules.
// These tests exercise those exact entry points through the TLS
// certificate-compression branch's own semantics — round-trip of a compressed
// certificate message — so a decompressor that broke under the version bump
// fails here rather than in production handshakes.
//
// Scope note: these are COMPATIBILITY tests, not defect-sensitive tests. They
// pass on both the vulnerable and the fixed pins, because a working
// decompressor round-trips valid input either way; that was verified against
// v1.1.0/v1.19.1 and is recorded in the handover. What they DO prove is that the
// security bump did not break the decode contract utls depends on. The actual
// advisory closure is evidenced by the govulncheck exit change (3 -> 0) on the
// same source, not by these assertions. This is also not live WAN/DPI evidence.

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// realisticCertificatePayload builds a payload shaped like the compressed
// certificate message utls decompresses: a TLS handshake message header
// followed by high-entropy bytes (a real certificate chain is largely random
// signature/key material, which is what stresses a Huffman/block decoder).
func realisticCertificatePayload(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, 4+size)
	// typeCertificate + uint24 uncompressed length, as utls reconstructs it.
	payload[0] = 11 // typeCertificate
	l := size
	payload[1] = byte(l >> 16)
	payload[2] = byte(l >> 8)
	payload[3] = byte(l)
	if _, err := rand.Read(payload[4:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return payload
}

// TestCertCompressionBrotliRoundTrip exercises brotli.NewReader — the exact
// call at utls u_handshake_client.go:72 — on the pinned security-fixed module.
func TestCertCompressionBrotliRoundTrip(t *testing.T) {
	for _, size := range []int{1, 64, 1024, 32 * 1024} {
		want := realisticCertificatePayload(t, size)

		var buf bytes.Buffer
		w := brotli.NewWriter(&buf)
		if _, err := w.Write(want); err != nil {
			t.Fatalf("size=%d: brotli write: %v", size, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("size=%d: brotli close: %v", size, err)
		}

		got, err := io.ReadAll(brotli.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			t.Fatalf("size=%d: brotli.NewReader/ReadAll: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size=%d: brotli round-trip mismatch (got %d bytes, want %d)", size, len(got), len(want))
		}
	}
}

// TestCertCompressionBrotliDecodesStreamed verifies the reader also works
// incrementally, which is how utls consumes it (io.ReadFull over a byte count,
// not ReadAll), so a buffering change in the fixed release cannot slip through.
func TestCertCompressionBrotliDecodesStreamed(t *testing.T) {
	want := realisticCertificatePayload(t, 4096)

	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(brotli.NewReader(bytes.NewReader(buf.Bytes())), got); err != nil {
		t.Fatalf("brotli io.ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("brotli streamed read mismatch")
	}
}

// TestCertCompressionZstdRoundTrip exercises zstd.NewReader — the exact call at
// utls u_handshake_client.go:84 — on the pinned security-fixed module.
func TestCertCompressionZstdRoundTrip(t *testing.T) {
	for _, size := range []int{1, 64, 1024, 32 * 1024} {
		want := realisticCertificatePayload(t, size)

		var buf bytes.Buffer
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatalf("size=%d: zstd.NewWriter: %v", size, err)
		}
		if _, err := w.Write(want); err != nil {
			t.Fatalf("size=%d: zstd write: %v", size, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("size=%d: zstd close: %v", size, err)
		}

		rc, err := zstd.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("size=%d: zstd.NewReader: %v", size, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("size=%d: zstd ReadAll: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size=%d: zstd round-trip mismatch (got %d bytes, want %d)", size, len(got), len(want))
		}
	}
}

// TestCertCompressionBrotliRejectsCorruptInput pins the negative direction: the
// fixed decompressor must still report a malformed stream as an error rather
// than returning silently-truncated data or hanging.
func TestCertCompressionBrotliRejectsCorruptInput(t *testing.T) {
	corrupt := []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03}
	if _, err := io.ReadAll(brotli.NewReader(bytes.NewReader(corrupt))); err == nil {
		t.Fatal("brotli accepted corrupt input without error")
	}
}
