package vpn

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
	"golang.org/x/crypto/curve25519"
)

type delayedPeerWrite struct {
	started chan struct{}
	release chan struct{}
	result  chan error
	device  *peerVirtualDevice
}

func (d *delayedPeerWrite) Read([]byte) (int, error) { return 0, nil }
func (d *delayedPeerWrite) Close() error             { return nil }
func (d *delayedPeerWrite) Write(packet []byte) (int, error) {
	d.started <- struct{}{}
	<-d.release
	n, err := d.device.Write(packet)
	d.result <- err
	return n, err
}

func TestTeardownFencesHandshakeBeforeWaitingForWrite(t *testing.T) {
	for _, action := range []string{"disconnect-session", "disconnect-user", "release-client", "idle-reap"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			svc, _, _, userID, _ := setupTestVPNService(t, setupTestDB(t))
			defer func() { _ = svc.Stop() }()
			if err := svc.Start(ctx); err != nil {
				t.Fatal(err)
			}

			hpKey, err := base64.StdEncoding.DecodeString(svc.cfg.HeaderProtectionKey)
			if err != nil {
				t.Fatal(err)
			}
			serverPub, err := base64.StdEncoding.DecodeString(svc.portalPubKey)
			if err != nil {
				t.Fatal(err)
			}
			packet, state, err := health.BuildAWGInitiationPacketObfuscated(serverPub, nil, nil, hpKey, svc.cfg.H1, svc.cfg.S1)
			if err != nil {
				t.Fatal(err)
			}
			clientPub, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint)
			if err != nil {
				t.Fatal(err)
			}
			peer := base64.StdEncoding.EncodeToString(clientPub)
			if _, err := svc.db.CreateConnection(ctx, &models.UserConnection{
				UserID: userID, ServerID: 0, Protocol: "awg", ClientID: peer, Name: "fenced-peer",
			}); err != nil {
				t.Fatal(err)
			}

			serverAddr := svc.endpoint.GetListenAddr().(*net.UDPAddr)
			client, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			oldClient, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer oldClient.Close()

			hookFired := make(chan string, 1)
			resume := make(chan struct{})
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
			}()
			svc.SetPreTransportCommitHookForTest(func(key, sessionID string) {
				if key == peer {
					hookFired <- sessionID
					<-resume
				}
			})
			if _, err := client.Write(packet); err != nil {
				t.Fatal(err)
			}
			var sessionID string
			select {
			case sessionID = <-hookFired:
			case <-time.After(3 * time.Second):
				t.Fatal("handshake did not reach pre-commit hook")
			}
			sess, ok := svc.sessionMgr.GetSessionByID(sessionID)
			if !ok {
				t.Fatal("handshake has no session")
			}

			// Model a previous key still usable for a return write admitted
			// before the new handshake commits.
			svc.endpoint.StoreTransportKeysForTest(peer, &endpoint.TransportKeys{
				SendKey: make([]byte, 32), RecvKey: make([]byte, 32), RemoteIndex: 1,
			})
			oldAddr := oldClient.LocalAddr().(*net.UDPAddr)
			svc.endpoint.RememberPeerForTest(oldAddr, peer, 1)
			dev := &delayedPeerWrite{
				started: make(chan struct{}, 1), release: make(chan struct{}), result: make(chan error, 1),
				device: &peerVirtualDevice{peerKey: peer, endpoint: svc.endpoint},
			}
			defer func() {
				select {
				case <-dev.release:
				default:
					close(dev.release)
				}
			}()
			svc.forwarder.AttachPeerDevice(peer, dev)
			svc.forwarder.StartPumps(ctx)
			if err := svc.forwarder.RouteBackendToClient(sess.BackendTunnelID, []byte("return packet"), sess.AssignedIP); err != nil {
				t.Fatal(err)
			}
			select {
			case <-dev.started:
			case <-time.After(3 * time.Second):
				t.Fatal("return write was not admitted")
			}

			done := make(chan error, 1)
			go func() {
				var err error
				switch action {
				case "disconnect-session":
					err = svc.DisconnectSession(ctx, sessionID)
				case "disconnect-user":
					err = svc.DisconnectUser(ctx, userID)
				case "release-client":
					err = svc.ReleaseClient(ctx, peer)
				case "idle-reap":
					svc.sessionMgr.SetSessionLastSeen(peer, time.Now().UTC().Add(-10*time.Minute))
					_, err = svc.endpoint.SweepTimedOutSessions(ctx)
				}
				done <- err
			}()

			deadline := time.Now().Add(3 * time.Second)
			for svc.forwarder.RouteSessionID(peer) != "" && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := svc.forwarder.RouteSessionID(peer); got != "" {
				t.Fatalf("route not retired: %s", got)
			}
			if got := svc.endpoint.PeerGeneration(peer); got <= sess.Generation {
				t.Fatalf("endpoint fence %d did not advance past handshake generation %d", got, sess.Generation)
			}
			if _, ok := svc.endpoint.TransportKeysFor(peer); !ok {
				t.Fatal("old keys were pruned before admitted write finished")
			}
			select {
			case err := <-done:
				t.Fatalf("%s returned before admitted write finished: %v", action, err)
			default:
			}

			close(resume)
			deadline = time.Now().Add(3 * time.Second)
			for svc.endpoint.StaleHandshakeDrops() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if svc.endpoint.StaleHandshakeDrops() == 0 {
				t.Fatal("stale handshake committed while route retirement waited")
			}
			if got := svc.endpoint.PeerEndpoint(peer); got == nil || got.String() != oldAddr.String() {
				t.Fatalf("stale handshake changed peer endpoint: %v", got)
			}
			if count := svc.endpoint.IndexTableCountForTest(); count != 0 {
				t.Fatalf("stale handshake leaked receiver index: %d entries", count)
			}
			_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			if n, err := client.Read(make([]byte, 2048)); err == nil {
				t.Fatalf("stale handshake emitted a %d-byte response", n)
			}

			close(dev.release)
			select {
			case err := <-dev.result:
				if err != nil {
					t.Fatalf("admitted write could not use old keys: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("admitted write did not finish")
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s did not finish retirement", action)
			}
			if _, ok := svc.endpoint.TransportKeysFor(peer); ok {
				t.Fatal("old keys survived completed teardown")
			}
			if svc.endpoint.HasPeerAddrForTest(peer) {
				t.Fatal("old endpoint survived completed teardown")
			}
		})
	}
}
