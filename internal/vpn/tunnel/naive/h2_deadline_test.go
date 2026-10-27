package naive

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDialer_H2_WriteDeadlineInterruptsBlockedWriteAndPreservesSibling(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()
	blackholeAddr, cleanupBlackhole := startBlackholeListener(t)

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()
	defer cleanupBlackhole()

	d, err := New(proxyAddr, models.NaiveProxyParams{
		Username: "testuser", Password: "testpass", Domain: testCamouflageDomain,
	})
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn1, err := d.DialContext(ctx, "tcp", blackholeAddr)
	if err != nil {
		t.Fatalf("DialContext blackhole: %v", err)
	}
	defer conn1.Close()
	conn2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext sibling: %v", err)
	}
	defer conn2.Close()

	echo := func(msg string) {
		t.Helper()
		_ = conn2.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn2.Write([]byte(msg)); err != nil {
			t.Fatalf("sibling write %q: %v", msg, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn2, got); err != nil || string(got) != msg {
			t.Fatalf("sibling echo %q: got %q, err %v", msg, got, err)
		}
	}
	echo("sibling alive before blocking")

	var written atomic.Int64
	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := conn1.Write(buf)
			written.Add(int64(n))
			if err != nil {
				writeErr <- err
				return
			}
		}
	}()

	// Wait until the writer stops making progress (blocked by flow control).
	last, stable := int64(-1), 0
	for deadline := time.Now().Add(10 * time.Second); stable < 5; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("writer never blocked (written=%d)", written.Load())
		}
		if cur := written.Load(); cur > 0 && cur == last {
			stable++
		} else {
			stable = 0
		}
		last = written.Load()
	}

	start := time.Now()
	if err := conn1.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	select {
	case err := <-writeErr:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked Write: got %v, want os.ErrDeadlineExceeded", err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("Write took %v after deadline, want < 2s", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Write not interrupted by write deadline")
	}

	// Sibling stream on the same pooled H2 connection still works.
	echo("sibling alive after write deadline")
}
