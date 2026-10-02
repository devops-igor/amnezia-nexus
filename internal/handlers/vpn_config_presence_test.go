package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// flagFixture drives the real PUT /api/vpn/config handler and reads the
// effective flags back the way the caller under test would observe them.
//
// The two persistence paths need different reads: with vpnSvc wired the GET
// handler answers from the service, but VPNGetConfigHandler falls back to a
// DEFAULT config when no service is wired, so the database-only path reads the
// stored row instead. Asserting through GET in both cases would have silently
// tested the fallback defaults rather than the stored config.
type flagFixture struct {
	router http.Handler
	h      *Handlers
	db     *database.DB
	// flags reads the currently effective (random_trailers, disable_cookies).
	flags func(t *testing.T) (bool, bool)
}

func newFlagFixture(t *testing.T, withSvc bool) flagFixture {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	if !withSvc {
		h.vpnSvc = nil
	}
	f := flagFixture{router: setupFullVPNRouter(h), h: h, db: db}
	if withSvc {
		f.flags = func(t *testing.T) (bool, bool) {
			t.Helper()
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
			w := httptest.NewRecorder()
			f.router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("GET /api/vpn/config expected 200, got %d", w.Code)
			}
			var cfg models.VPNConfig
			if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
				t.Fatalf("GET response is not valid VPNConfig JSON: %v", err)
			}
			return cfg.RandomTrailers, cfg.DisableCookies
		}
		return f
	}
	f.flags = func(t *testing.T) (bool, bool) {
		t.Helper()
		cfg, err := db.GetVPNConfig(context.Background())
		if err != nil || cfg == nil {
			t.Fatalf("db.GetVPNConfig: %v", err)
		}
		return cfg.RandomTrailers, cfg.DisableCookies
	}
	return f
}

func (f flagFixture) put(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f flagFixture) putOK(t *testing.T, body string) {
	t.Helper()
	if w := f.put(t, body); w.Code != http.StatusOK {
		t.Fatalf("PUT /api/vpn/config (%s) expected 200, got %d: %s", body, w.Code, w.Body.String())
	}
}

// setFlags puts the two protocol booleans into a known state through the real
// handler, so no subtest ever bypasses the code path under test.
func (f flagFixture) setFlags(t *testing.T, trailers, cookies bool) {
	t.Helper()
	body, err := json.Marshal(map[string]bool{
		"random_trailers": trailers,
		"disable_cookies": cookies,
	})
	if err != nil {
		t.Fatalf("marshal flags: %v", err)
	}
	f.putOK(t, string(body))
}

func (f flagFixture) assertFlags(t *testing.T, wantTrailers, wantCookies bool) {
	t.Helper()
	gotTrailers, gotCookies := f.flags(t)
	if gotTrailers != wantTrailers {
		t.Errorf("random_trailers = %v, want %v", gotTrailers, wantTrailers)
	}
	if gotCookies != wantCookies {
		t.Errorf("disable_cookies = %v, want %v", gotCookies, wantCookies)
	}
}

// TestVPNUpdateConfigHandler_PresenceSemantics pins PRESENCE semantics for the
// two AWG protocol-parameter booleans on a partial update (issue #391 round 4b,
// finding 3):
//
//	key absent        -> preserve the stored value
//	key present false -> set false
//	key present true  -> set true
//
// A bool cannot tell "explicitly false" from "omitted", so the handler must
// consult the raw JSON it already parses. Without that, an unrelated partial
// update such as {"health_threshold_ms": 750} unmarshals both flags to false
// and SaveVPNConfig persists false, silently erasing a live protocol flag.
//
// Every subtest runs BOTH with and without vpnSvc wired, because the handler
// takes two different persistence paths (h.vpnSvc.UpdateConfig and
// h.db.SaveVPNConfig) and both had to be fixed.
func TestVPNUpdateConfigHandler_PresenceSemantics(t *testing.T) {
	for _, withSvc := range []bool{true, false} {
		name := "with vpnSvc"
		if !withSvc {
			name = "without vpnSvc"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("omitted flags preserve stored values", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, true, true)
				f.assertFlags(t, true, true)

				// An update that mentions NEITHER flag must preserve both.
				f.putOK(t, `{"health_threshold_ms": 750}`)
				f.assertFlags(t, true, true)
				f.putOK(t, `{"algorithm":"least_conn"}`)
				f.assertFlags(t, true, true)
			})

			t.Run("explicit false is applied", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, true, true)
				f.putOK(t, `{"random_trailers": false, "disable_cookies": false}`)
				f.assertFlags(t, false, false)
			})

			t.Run("explicit true is applied", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, false, false)
				f.putOK(t, `{"random_trailers": true, "disable_cookies": true}`)
				f.assertFlags(t, true, true)
			})

			t.Run("explicit false is applied from true and vice versa", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, true, true)
				f.putOK(t, `{"random_trailers": false}`)
				f.assertFlags(t, false, true)

				f.putOK(t, `{"disable_cookies": false}`)
				f.assertFlags(t, false, false)

				f.putOK(t, `{"random_trailers": true}`)
				f.assertFlags(t, true, false)
			})

			t.Run("unrelated update changes neither flag", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, true, true)
				f.putOK(t, `{"health_threshold_ms": 750}`)
				f.assertFlags(t, true, true)

				f.putOK(t, `{}`)
				f.assertFlags(t, true, true)
			})

			t.Run("presence is matched case-insensitively", func(t *testing.T) {
				f := newFlagFixture(t, withSvc)
				f.setFlags(t, false, false)
				// encoding/json matches field tags case-insensitively, so
				// presence must be tracked the same way: these decode into
				// the fields and must not be treated as absent.
				f.putOK(t, `{"RANDOM_TRAILERS": true, "Disable_Cookies": true}`)
				f.assertFlags(t, true, true)
			})
		})
	}
}

// TestVPNUpdateConfigHandler_ActiveSynchronizerAcceptsUnrelatedUpdate proves the
// user-visible half of finding 3: with a peer synchronizer armed on the
// database, an unrelated partial update used to be REJECTED as a prohibited
// protocol-parameter change.
//
// The rejection was a false positive. SaveVPNConfig consults the listener's
// ValidatePortalConfig before committing, and that guard compares
// RandomTrailers/DisableCookies against the live device settings. Because the
// merge had already dropped both flags to false, an update that never
// mentioned them looked like a change to a live protocol parameter and the
// whole settings update was refused.
func TestVPNUpdateConfigHandler_ActiveSynchronizerAcceptsUnrelatedUpdate(t *testing.T) {
	for _, withSvc := range []bool{true, false} {
		name := "with vpnSvc"
		if !withSvc {
			name = "without vpnSvc"
		}
		t.Run(name, func(t *testing.T) {
			f := newFlagFixture(t, withSvc)

			// Establish the live protocol flags BEFORE arming the guard: the
			// guard rejects protocol-parameter changes, and establishing them
			// is exactly such a change.
			f.setFlags(t, true, true)
			f.assertFlags(t, true, true)

			// Arm a live synchronizer over the portal config. It snapshots
			// the live settings once and then enforces exactly the production
			// rule from internal/vpn/peer_sync.go: a change to an upstream
			// listener parameter (including the two booleans) requires a
			// controlled restart.
			guard := &protocolGuardListener{settings: *mustGetConfig(t, f.db, withSvc, f.h)}
			detach, err := f.db.SubscribePeerChanges(guard)
			if err != nil {
				t.Fatalf("SubscribePeerChanges: %v", err)
			}
			t.Cleanup(detach)

			// An unrelated settings update must now be accepted, because the
			// merge preserves the live protocol flags.
			f.putOK(t, `{"health_threshold_ms": 750}`)
			f.assertFlags(t, true, true)

			f.putOK(t, `{"algorithm":"least_conn"}`)
			f.assertFlags(t, true, true)

			f.putOK(t, `{"affinity_ttl_minutes": 45}`)
			f.assertFlags(t, true, true)

			// The guard is genuinely armed: a REAL protocol-parameter change
			// is still refused. Without this assertion the test could pass
			// simply because no guard was enforcing anything.
			if w := f.put(t, `{"random_trailers": false}`); w.Code == http.StatusOK {
				t.Fatal("an explicit protocol-parameter change was accepted while the synchronizer requires a controlled restart")
			}
			if guard.calls == 0 {
				t.Fatal("ValidatePortalConfig was never consulted: the guard was not armed")
			}
		})
	}
}

// protocolGuardListener mirrors the production ValidatePortalConfig rule from
// internal/vpn/peer_sync.go: a change to any upstream listener parameter
// requires the portal listener to be stopped and restarted first.
type protocolGuardListener struct {
	settings models.VPNConfig
	calls    int
}

func (l *protocolGuardListener) ReconcilePeers(context.Context) error { return nil }

func (l *protocolGuardListener) ValidatePortalConfig(cfg *models.VPNConfig) error {
	l.calls++
	if cfg == nil {
		return &portalGuardError{"nil VPN configuration"}
	}
	p := l.settings
	if cfg.ServerPublicKey != p.ServerPublicKey || cfg.ListenPort != p.ListenPort ||
		cfg.SubnetCIDR != p.SubnetCIDR || cfg.H1 != p.H1 || cfg.H2 != p.H2 ||
		cfg.H3 != p.H3 || cfg.H4 != p.H4 || cfg.S1 != p.S1 || cfg.S2 != p.S2 ||
		cfg.S3 != p.S3 || cfg.S4 != p.S4 || cfg.HeaderProtectionKey != p.HeaderProtectionKey ||
		cfg.ContentPaddingAddition != p.ContentPaddingAddition ||
		cfg.RandomTrailers != p.RandomTrailers || cfg.DisableCookies != p.DisableCookies {
		return &portalGuardError{"portal AWG parameters require stopping the upstream listener before update and restarting it afterward"}
	}
	return nil
}

type portalGuardError struct{ msg string }

func (e *portalGuardError) Error() string { return e.msg }

// mustGetConfig reads the current config from whichever persistence path the
// handler under test uses, so the guard snapshots exactly what is live.
func mustGetConfig(t *testing.T, db *database.DB, withSvc bool, h *Handlers) *models.VPNConfig {
	t.Helper()
	ctx := context.Background()
	var cfg *models.VPNConfig
	if withSvc && h.vpnSvc != nil {
		var err error
		cfg, err = h.vpnSvc.GetConfig(ctx)
		if err != nil {
			t.Fatalf("vpnSvc.GetConfig: %v", err)
		}
	} else {
		var err error
		cfg, err = db.GetVPNConfig(ctx)
		if err != nil {
			t.Fatalf("db.GetVPNConfig: %v", err)
		}
	}
	if cfg == nil {
		t.Fatal("no current VPN config to snapshot")
	}
	return cfg
}
