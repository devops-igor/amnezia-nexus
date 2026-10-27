package naive

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// After a transport-level H3 failure, dials inside the cooldown go straight to H2
// (no 2s H3 timeout), and H3 is retried and the cooldown cleared once it elapses.
func TestDialer_H3_FailureCooldownSkipsH3ThenRecovers(t *testing.T) {
	prev := h3FailureCooldown
	h3FailureCooldown = 2 * time.Second
	t.Cleanup(func() { h3FailureCooldown = prev })

	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()
	proxyAddr, drop, cleanupServer := setupDualStackH2H3Server(t, "testuser", "testpass")
	defer cleanupServer()

	d, err := New(proxyAddr, models.NaiveProxyParams{
		Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: true,
	})
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	dial := func() (any, time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", echoAddr)
		el := time.Since(start)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c, el
	}

	if c, _ := dial(); !isH3(c) {
		t.Fatalf("first dial: got %T, want *h3Conn", c)
	}

	drop.Store(true)
	// First dial under UDP loss pays the H3 timeout, falls back to H2, starts the cooldown.
	if c, el := dial(); isH3(c) || el < time.Second {
		t.Fatalf("dial under UDP drop: got %T in %v, want H2 fallback after H3 timeout", c, el)
	}
	if d.h3CooldownUntil.Load() == 0 {
		t.Fatal("cooldown not recorded after H3 timeout")
	}

	// Inside the cooldown: immediate H2, no 2s H3 penalty.
	if c, el := dial(); isH3(c) || el > 500*time.Millisecond {
		t.Fatalf("dial in cooldown: got %T in %v, want immediate H2", c, el)
	}

	// Cooldown elapses and UDP recovers: H3 again, cooldown reset.
	drop.Store(false)
	for time.Now().UnixNano() < d.h3CooldownUntil.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	if c, _ := dial(); !isH3(c) {
		t.Fatalf("dial after cooldown: got %T, want *h3Conn", c)
	}
	if d.h3CooldownUntil.Load() != 0 {
		t.Fatal("cooldown not reset after successful H3 dial")
	}
}

func isH3(c any) bool { _, ok := c.(*h3Conn); return ok }
