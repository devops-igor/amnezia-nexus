package awg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func TestAWGManager_ServerLock_Isolation(t *testing.T) {
	mgrDefault := NewAWGManager(nil)
	regCustom := NewServerLockRegistry()

	mgrWithLocks := NewAWGManagerWithServerLocks(nil, regCustom)
	mgrShared := NewAWGManagerWithServerLocks(nil, regCustom)

	const serverID = int64(101)

	lockDefault := mgrDefault.getServerLock(serverID)
	lockCustom := mgrWithLocks.getServerLock(serverID)
	lockShared := mgrShared.getServerLock(serverID)

	if lockDefault == nil || lockCustom == nil || lockShared == nil {
		t.Fatal("expected non-nil locks from getServerLock")
	}

	if lockDefault == lockCustom {
		t.Fatalf("expected isolated locks between default global registry and custom registry, got same pointer: %p", lockDefault)
	}

	if lockCustom != lockShared {
		t.Fatalf("expected same lock pointer for managers sharing the same registry, got %p vs %p", lockCustom, lockShared)
	}
}

func TestAWGManager_ServerLock_NilFallback(t *testing.T) {
	const serverID = int64(202)
	expectedLock := globalServerLocks.getLock(serverID)

	var nilMgr *AWGManager
	if lock := nilMgr.getServerLock(serverID); lock != expectedLock {
		t.Fatalf("expected nil manager to fall back to globalServerLocks, got %p, want %p", lock, expectedLock)
	}

	emptyMgr := &AWGManager{}
	if lock := emptyMgr.getServerLock(serverID); lock != expectedLock {
		t.Fatalf("expected manager with nil serverLocks to fall back to globalServerLocks, got %p, want %p", lock, expectedLock)
	}
}

func TestAWGManager_ServerLock_ConcurrentAccess(t *testing.T) {
	reg1 := NewServerLockRegistry()
	reg2 := NewServerLockRegistry()

	mgr1 := NewAWGManagerWithServerLocks(nil, reg1)
	mgr2 := NewAWGManagerWithServerLocks(nil, reg2)
	mgrDefault := NewAWGManager(nil)

	const workers = 16
	const iterations = 100
	var wg sync.WaitGroup

	// Per-server counters protected by respective per-server locks
	counters1 := make([]int, 4)
	counters2 := make([]int, 4)
	countersDefault := make([]int, 4)

	for i := 0; i < workers; i++ {
		wg.Add(3)
		serverID := int64(i % 4)

		go func(id int64) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				l := mgr1.getServerLock(id)
				l.Lock()
				counters1[id]++
				l.Unlock()
			}
		}(serverID)

		go func(id int64) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				l := mgr2.getServerLock(id)
				l.Lock()
				counters2[id]++
				l.Unlock()
			}
		}(serverID)

		go func(id int64) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				l := mgrDefault.getServerLock(id)
				l.Lock()
				countersDefault[id]++
				l.Unlock()
			}
		}(serverID)
	}

	wg.Wait()

	expectedCount := (workers / 4) * iterations
	for id := int64(0); id < 4; id++ {
		if counters1[id] != expectedCount {
			t.Errorf("server %d: counters1 = %d, want %d", id, counters1[id], expectedCount)
		}
		if counters2[id] != expectedCount {
			t.Errorf("server %d: counters2 = %d, want %d", id, counters2[id], expectedCount)
		}
		if countersDefault[id] != expectedCount {
			t.Errorf("server %d: countersDefault = %d, want %d", id, countersDefault[id], expectedCount)
		}
		if lock1, lock2 := mgr1.getServerLock(id), mgr2.getServerLock(id); lock1 == lock2 {
			t.Errorf("server %d: expected distinct locks for mgr1 and mgr2, got %p", id, lock1)
		}
	}
}

type stalledSessionServer struct {
	listener         net.Listener
	config           *gossh.ServerConfig
	heartbeatOpening chan struct{}
	heartbeatOnce    sync.Once
	channelCount     atomic.Int32
	locked           atomic.Bool
}

func newStalledSessionServer(t *testing.T) *stalledSessionServer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create SSH host signer: %v", err)
	}

	config := &gossh.ServerConfig{
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH connections: %v", err)
	}

	server := &stalledSessionServer{
		listener:         listener,
		config:           config,
		heartbeatOpening: make(chan struct{}),
	}
	go server.serve(t)
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func (s *stalledSessionServer) serve(t *testing.T) {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	serverConn, channels, requests, err := gossh.NewServerConn(conn, s.config)
	if err != nil {
		_ = conn.Close()
		t.Errorf("SSH handshake failed: %v", err)
		return
	}
	defer serverConn.Close()
	go gossh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if s.channelCount.Add(1) == 2 {
			s.heartbeatOnce.Do(func() { close(s.heartbeatOpening) })
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(channel, channelRequests)
	}
}

func (s *stalledSessionServer) handleSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" || len(request.Payload) < 4 {
			_ = request.Reply(false, nil)
			continue
		}
		commandLength := binary.BigEndian.Uint32(request.Payload[:4])
		if int(commandLength) > len(request.Payload)-4 {
			_ = request.Reply(false, nil)
			continue
		}
		command := string(request.Payload[4 : 4+commandLength])
		_ = request.Reply(true, nil)

		exitCode := uint32(0)
		switch {
		case strings.Contains(command, "cur_owner=") && strings.Contains(command, "rm -rf"):
			s.locked.Store(false)
		case strings.Contains(command, "flock_path="):
			if !s.locked.CompareAndSwap(false, true) {
				exitCode = 1
			}
		}
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, exitCode)
		_, _ = channel.SendRequest("exit-status", false, status)
		return
	}
}

func TestRemoteLock_UnlockCancelsStalledHeartbeatSessionOpen(t *testing.T) {
	server := newStalledSessionServer(t)
	address := server.listener.Addr().(*net.TCPAddr)
	client, err := ssh.Dial(context.Background(), ssh.Config{
		Host:            address.IP.String(),
		Port:            address.Port,
		User:            "root",
		Password:        "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial stalled-session SSH server: %v", err)
	}
	defer client.Close()

	unlock, err := AcquireRemoteServerLockWithHeartbeat(
		context.Background(), client, "server_636", 10*time.Millisecond, time.Second,
	)
	if err != nil {
		t.Fatalf("acquire remote lock: %v", err)
	}

	select {
	case <-server.heartbeatOpening:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not attempt to open an SSH session")
	}

	unlockDone := make(chan struct{})
	started := time.Now()
	go func() {
		unlock()
		close(unlockDone)
	}()
	select {
	case <-unlockDone:
		if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
			t.Fatalf("unlock took %s with a stalled heartbeat session open", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("unlock did not cancel stalled heartbeat session opening")
	}

	reacquireCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	secondUnlock, err := AcquireRemoteServerLockWithHeartbeat(
		reacquireCtx, client, "server_636", time.Hour, time.Second,
	)
	if err != nil {
		t.Fatalf("reacquire remote lock after stalled heartbeat: %v", err)
	}
	secondUnlock()
}
