package scanner

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

func TestScanSNI_RefusalIsNotFailedTLSMeasurement(t *testing.T) {
	var calls int
	dial := func(context.Context, string, string) (net.Conn, error) { calls++; return nil, ssh.ErrProviderAbsent }
	report, err := ScanSNI(context.Background(), "127.0.0.1", ScannerOptions{Domains: []string{"127.0.0.1"}, Concurrency: 1, Timeout: time.Second, DialContext: dial})
	if calls != 1 || !errors.Is(err, ssh.ErrProviderAbsent) || report != nil {
		t.Fatalf("refusal became measured report: calls=%d report=%+v err=%v", calls, report, err)
	}
	_, err = ScanSNI(context.Background(), "127.0.0.1", ScannerOptions{Domains: []string{"127.0.0.1"}, Concurrency: 1, Timeout: time.Second, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("actual network failure")
	}})
	if err != nil {
		t.Fatalf("ordinary failed TLS measurement changed: %v", err)
	}
}
