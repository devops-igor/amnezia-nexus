package gigahost

// Completeness contract for the distribution and image envelopes.
//
// These parsers feed both the ordering page's catalog AND the purchase path's
// image selection, so their envelope rules are load-bearing. The distinction under
// test is narrow and deliberate:
//
//   - an explicitly empty array is a legitimate provider answer ("this account has
//     no distributions", "this distribution publishes no image") and must stay a
//     successful read;
//   - a missing `data` key, a JSON null, or an entry without its required identity
//     is a broken response and must be an error.
//
// Go's decoder accepts the second group silently as an empty list, which is what
// made a malformed HTTP-200 response indistinguishable from a genuinely empty one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// envelopeServer serves fixed bodies per path suffix and counts requests.
func envelopeServer(t *testing.T, distroBody, imageBody string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/reinstall/distro"):
			_, _ = w.Write([]byte(distroBody))
		case strings.Contains(r.URL.Path, "/reinstall/distro/"):
			_, _ = w.Write([]byte(imageBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

const validDistroBody = `{"meta":{"status":200},"data":[{"dist_id":"1","dist_name":"Debian","dist_active":"1"}]}`
const validImageBody = `{"meta":{"status":200},"data":[{"os_id":"12","dist_id":"1","os_name":"Debian 12"}]}`

// TestGetOperatingSystems_RejectsMalformedEnvelopes covers the malformed shapes an
// upstream fault actually produces, at the client boundary where the parser lives.
func TestGetOperatingSystems_RejectsMalformedEnvelopes(t *testing.T) {
	cases := []struct {
		name       string
		distroBody string
		imageBody  string
	}{
		{"missing distribution data", `{"meta":{"status":200}}`, validImageBody},
		{"null distribution data", `{"meta":{"status":200},"data":null}`, validImageBody},
		{"null distribution body", `null`, validImageBody},
		{"distribution without dist_id", `{"meta":{"status":200},"data":[{"dist_name":"Debian"}]}`, validImageBody},
		{"missing image data", validDistroBody, `{"meta":{"status":200}}`},
		{"null image data", validDistroBody, `{"meta":{"status":200},"data":null}`},
		{"null image body", validDistroBody, `null`},
		{"image without os_id", validDistroBody, `{"meta":{"status":200},"data":[{"os_name":"Debian 12"}]}`},
		{"image with negative os_id", validDistroBody, `{"meta":{"status":200},"data":[{"os_id":"-3","os_name":"Debian 12"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := envelopeServer(t, tc.distroBody, tc.imageBody, nil)
			defer server.Close()
			c, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("e", 64)})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			systems, err := c.GetOperatingSystems(context.Background())
			if err == nil {
				t.Fatalf("expected an error for %s, got nil (images: %+v)", tc.name, systems)
			}
			// The error must name the malformed envelope rather than reporting an
			// empty result, so a caller can tell a broken response from a valid
			// empty one.
			if !errors.Is(err, errMalformedDistributionEnvelope) && !errors.Is(err, errMalformedImageEnvelope) {
				t.Errorf("error = %v, want a malformed-envelope error", err)
			}
		})
	}
}

// TestGetOperatingSystems_ExplicitEmptyIsSuccess is the positive control: the fix
// must not turn a legitimate empty answer into a failure.
func TestGetOperatingSystems_ExplicitEmptyIsSuccess(t *testing.T) {
	t.Run("empty distribution list", func(t *testing.T) {
		server := envelopeServer(t, `{"meta":{"status":200},"data":[]}`, validImageBody, nil)
		defer server.Close()
		c, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("f", 64)})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		systems, err := c.GetOperatingSystems(context.Background())
		if err != nil {
			t.Fatalf("an explicitly empty distribution list must be a successful read: %v", err)
		}
		if len(systems) != 0 {
			t.Errorf("images = %d, want 0", len(systems))
		}
	})

	t.Run("distribution publishing no image", func(t *testing.T) {
		server := envelopeServer(t, validDistroBody, `{"meta":{"status":200},"data":[]}`, nil)
		defer server.Close()
		c, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("f", 64)})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		systems, err := c.GetOperatingSystems(context.Background())
		if err != nil {
			t.Fatalf("a distribution with an explicitly empty image list must be a successful read: %v", err)
		}
		if len(systems) != 0 {
			t.Errorf("images = %d, want 0", len(systems))
		}
	})

	t.Run("documented bodies still parse", func(t *testing.T) {
		server := envelopeServer(t, validDistroBody, validImageBody, nil)
		defer server.Close()
		c, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("f", 64)})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		systems, err := c.GetOperatingSystems(context.Background())
		if err != nil {
			t.Fatalf("documented bodies must parse: %v", err)
		}
		if len(systems) != 1 || systems[0].OSID != 12 {
			t.Fatalf("images = %+v, want the documented os_id 12", systems)
		}
		if systems[0].DistName != "Debian" {
			t.Errorf("dist name = %q, want it labeled from the distribution list", systems[0].DistName)
		}
	})
}

// TestGetOperatingSystems_MalformedDistributionStopsTheRead proves the malformed
// failure is not partially skipped: a broken distribution list fails the whole
// call, which is what makes the caller's retry/backoff path fire.
func TestGetOperatingSystems_MalformedDistributionStopsTheRead(t *testing.T) {
	var calls atomic.Int32
	server := envelopeServer(t, `{"meta":{"status":200}}`, validImageBody, &calls)
	defer server.Close()
	c, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetOperatingSystems(context.Background()); err == nil {
		t.Fatal("expected an error for a malformed distribution list")
	}
	// The distribution list is the first read, so a rejection must not proceed to
	// per-distribution image reads at all.
	if got := calls.Load(); got != 1 {
		t.Errorf("provider calls = %d, want 1 (the read must stop at the broken envelope)", got)
	}
}
