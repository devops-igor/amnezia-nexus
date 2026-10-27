package naive

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDialer_H3_CloseUnblocksBlockedWriterAndPreservesSibling(t *testing.T) {
	// 1. Setup TCP echo server for sibling stream
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// 2. Setup TCP blackhole listener (accepts but never reads data) to trigger backpressure
	blackholeAddr, cleanupBlackhole := startBlackholeListener(t)

	// 3. Setup H3 test server
	proxyAddr, cleanupH3 := setupTestH3Server(t, "testuser", "testpass", true)
	defer cleanupH3()
	defer cleanupBlackhole() // Release target before waiting for server shutdown.

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 4. Dial stream 1 to blackhole (will be blocked by flow control backpressure)
	conn1, err := d.DialContext(ctx, "tcp", blackholeAddr)
	if err != nil {
		t.Fatalf("DialContext conn1 (blackhole): %v", err)
	}
	defer conn1.Close()

	// 5. Dial stream 2 to echo server (sibling stream on same pooled QUIC connection)
	conn2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext conn2 (sibling): %v", err)
	}
	defer conn2.Close()

	// Verify sibling stream is healthy initially
	initialMsg := []byte("hello sibling stream before conn1 blocked")
	if _, err := conn2.Write(initialMsg); err != nil {
		t.Fatalf("conn2 initial write failed: %v", err)
	}
	initRecv := make([]byte, len(initialMsg))
	if _, err := io.ReadFull(conn2, initRecv); err != nil {
		t.Fatalf("conn2 initial read failed: %v", err)
	}
	if !bytes.Equal(initRecv, initialMsg) {
		t.Fatalf("conn2 initial payload mismatch: got %q, want %q", initRecv, initialMsg)
	}

	// 6. Spawn goroutine to write to conn1 continuously until blocked by backpressure
	writeErrCh := make(chan error, 1)
	writeStarted := make(chan struct{})
	var bytesWritten atomic.Int64
	var writeBlocked atomic.Bool

	go func() {
		close(writeStarted)
		// 64 KiB chunks
		buf := make([]byte, 64*1024)
		for {
			writeBlocked.Store(true)
			n, err := conn1.Write(buf)
			writeBlocked.Store(false)
			if err != nil {
				writeErrCh <- err
				return
			}
			bytesWritten.Add(int64(n))
		}
	}()

	<-writeStarted

	// Wait until conn1 writer has written data and is blocked waiting for flow control
	deadline := time.Now().Add(10 * time.Second)
	blocked := false
	last := int64(-1)
	stable := 0
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		cur := bytesWritten.Load()
		if cur > 0 && cur == last && writeBlocked.Load() {
			stable++
			if stable >= 5 {
				blocked = true
				break
			}
		} else {
			stable = 0
		}
		last = cur
	}
	if !blocked {
		t.Fatalf("conn1 writer did not block under backpressure (bytesWritten=%d)", bytesWritten.Load())
	}

	// 7. Call Close() on conn1 while writer is blocked.
	// CancelWrite must promptly abort and unblock the blocked Write() call.
	closeStart := time.Now()
	if err := conn1.Close(); err != nil {
		t.Fatalf("conn1.Close(): %v", err)
	}

	select {
	case err := <-writeErrCh:
		if err == nil {
			t.Fatal("expected conn1.Write to return error on Close(), got nil")
		}
		duration := time.Since(closeStart)
		t.Logf("conn1.Write promptly unblocked after %v with error: %v", duration, err)
		if duration > 1*time.Second {
			t.Fatalf("conn1.Write took %v to unblock, expected < 1s", duration)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("conn1.Write remained blocked after conn1.Close()")
	}

	// 8. Assert sibling stream conn2 is STILL ALIVE and can exchange data normally
	siblingMsg := []byte("sibling stream still alive after conn1 closed")
	if _, err := conn2.Write(siblingMsg); err != nil {
		t.Fatalf("conn2 write failed after conn1.Close(): %v", err)
	}
	sibRecv := make([]byte, len(siblingMsg))
	if _, err := io.ReadFull(conn2, sibRecv); err != nil {
		t.Fatalf("conn2 read failed after conn1.Close(): %v", err)
	}
	if !bytes.Equal(sibRecv, siblingMsg) {
		t.Fatalf("conn2 payload mismatch after conn1.Close(): got %q, want %q", sibRecv, siblingMsg)
	}

	// 9. Clean up conn2 gracefully
	if err := conn2.Close(); err != nil {
		t.Fatalf("conn2.Close(): %v", err)
	}
}
