package scanner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeTLSH2HandshakeHonorsCandidateTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	release := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-release
	}()
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
		<-serverDone
	})

	const timeout = 100 * time.Millisecond
	result := make(chan ProbeResult, 1)
	start := time.Now()
	go func() {
		result <- ProbeTLSH2(context.Background(), listener.Addr().String(), ProbeOptions{Timeout: timeout})
	}()

	select {
	case res := <-result:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("probe took %s with candidate timeout %s", elapsed, timeout)
		}
		if !strings.Contains(res.Error, "tls handshake failed") {
			t.Fatalf("probe error = %q, want TLS handshake failure", res.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not terminate after candidate timeout")
	}
}
