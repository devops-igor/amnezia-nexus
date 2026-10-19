package awg

import (
	"sync"
	"testing"
)

func TestAWGManager_ServerLock_Isolation(t *testing.T) {
	mgrDefault := NewAWGManager(nil)
	regCustom := NewServerLockRegistry()

	mgrWithLocks := NewAWGManagerWithServerLocks(nil, regCustom)
	mgrSetter := NewAWGManager(nil)
	mgrSetter.SetServerLockRegistryForTest(regCustom)

	const serverID = int64(101)

	lockDefault := mgrDefault.getServerLock(serverID)
	lockCustom := mgrWithLocks.getServerLock(serverID)
	lockSetter := mgrSetter.getServerLock(serverID)

	if lockDefault == nil || lockCustom == nil || lockSetter == nil {
		t.Fatal("expected non-nil locks from getServerLock")
	}

	if lockDefault == lockCustom {
		t.Fatalf("expected isolated locks between default global registry and custom registry, got same pointer: %p", lockDefault)
	}

	if lockCustom != lockSetter {
		t.Fatalf("expected same lock pointer for managers sharing the same registry, got %p vs %p", lockCustom, lockSetter)
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
}
