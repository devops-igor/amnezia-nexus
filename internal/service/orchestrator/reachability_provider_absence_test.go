package orchestrator

// Probe suppression for a server the provider's inventory has confirmed absent.
//
// The assertion is the connection count on a real listener, not a log line: once a
// server is recorded absent, a cycle produces no TCP attempt against it, while a
// server the provider still lists is dialed as before.

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestOrchestrator_CheckServerReachability_SkipsProviderAbsentServer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// One listener for both servers: every connection that arrives on it is a
	// probe that was actually attempted.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	var accepted int32
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			_ = conn.Close()
		}
	}()
	defer func() {
		_ = ln.Close()
		<-acceptDone
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("failed to read the listener port from %q: %v", portStr, err)
	}

	absentID, err := db.CreateServer(ctx, &models.Server{
		Name:    "Provider absent",
		Host:    "127.0.0.1",
		SSHPort: port,
	})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveID, err := db.CreateServer(ctx, &models.Server{
		Name:    "Still listed",
		Host:    "127.0.0.1",
		SSHPort: port,
	})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}

	orch := New(db, nil)

	// First cycle: the provider still lists both, so both are dialed. This is the
	// baseline the suppression is measured against.
	if _, err := orch.CheckServerReachability(ctx); err != nil {
		t.Fatalf("baseline reachability cycle failed: %v", err)
	}
	waitAccepted(t, &accepted, 2)
	if got := atomic.LoadInt32(&accepted); got != 2 {
		t.Fatalf("the baseline cycle dialed %d servers, want 2", got)
	}

	// The provider's inventory no longer lists one of them.
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC(), ""); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}
	atomic.StoreInt32(&accepted, 0)

	results, err := orch.CheckServerReachability(ctx)
	if err != nil {
		t.Fatalf("reachability cycle with an absent server failed: %v", err)
	}

	// The dialing has already happened by the time the cycle returned, so waiting
	// for the accept loop to register it is all that is needed before counting.
	waitAccepted(t, &accepted, 1)
	if got := atomic.LoadInt32(&accepted); got != 1 {
		t.Fatalf("expected exactly one connection attempt (the listed server), got %d", got)
	}

	if _, ok := results[liveID]; !ok {
		t.Fatalf("the listed server was not probed: %+v", results)
	}
	if reachable, _ := results[liveID]["reachable"].(bool); !reachable {
		t.Fatalf("the listed server should be reachable: %+v", results[liveID])
	}

	// The absent server keeps the observation the baseline cycle made rather than
	// being dropped into an unprobed state: refusing to dial is not a status change.
	absentResult, ok := results[absentID]
	if !ok {
		t.Fatal("the absent server lost its previous reachability observation")
	}
	if reachable, _ := absentResult["reachable"].(bool); !reachable {
		t.Fatalf("the carried-over observation changed: %+v", absentResult)
	}
	status, err := db.GetServerStatus(ctx, absentID)
	if err != nil {
		t.Fatalf("failed to read the absent server's status: %v", err)
	}
	if status != models.ReachabilityOnline {
		t.Fatalf("a refused probe rewrote the reachability status to %q", status)
	}
}

// waitAccepted blocks until the listener has accepted at least want connections,
// or fails the test once the wait stops being plausible.
func waitAccepted(t *testing.T, accepted *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(accepted) < want {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d expected connections reached the listener", atomic.LoadInt32(accepted), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
