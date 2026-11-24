package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestProxyQualification_AbsentOpensNoConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{Name: "qualification", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(models.VLESSRealityParams{UUID: "00000000-0000-0000-0000-000000000001", PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	tun := &models.BackendTunnel{ServerID: id, Protocol: models.ProtocolVLESS, Endpoint: listener.Addr().String(), ProtocolParams: params, Status: models.TunnelStatusActive, Enabled: true, LatencyMS: 17}
	before := *tun
	hp := NewHealthProber(NewPool(db), db, HealthConfig{Timeout: time.Second})
	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	latency, err := hp.QualifyProxyTraffic(ctx, tun)
	if !errors.Is(err, ErrProviderAbsent) || latency != 0 {
		t.Errorf("absent qualification = (%d, %v), want unmeasured refusal", latency, err)
	}
	if accepts.Load() != 0 {
		t.Errorf("absent qualification opened %d connections", accepts.Load())
	}
	if !reflect.DeepEqual(before, *tun) {
		t.Error("refusal changed prior tunnel observation")
	}
	if err := db.SetServerProviderAbsence(ctx, id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	_, err = hp.QualifyProxyTraffic(ctx, tun)
	if err == nil || errors.Is(err, ErrProviderAbsent) {
		t.Errorf("listed control = %v, want actual handshake failure", err)
	}
	if accepts.Load() != 1 {
		t.Errorf("listed control connection count = %d, want 1", accepts.Load())
	}
	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var hooks int
	hp.SetProxyTrafficProbeFunc(func(context.Context, *models.BackendTunnel) (int64, error) { hooks++; return 9, nil })
	if _, err := hp.QualifyProxyTraffic(ctx, tun); !errors.Is(err, ErrProviderAbsent) || hooks != 0 {
		t.Errorf("override bypassed admission: %v, calls=%d", err, hooks)
	}
}
