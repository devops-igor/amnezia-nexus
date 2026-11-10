package virtualtun

import (
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// drainEvents ranges over vt.Events until it closes, reporting what it saw.
func drainEvents(vt *VirtualTUN) <-chan []tun.Event {
	ch := make(chan []tun.Event, 1)
	go func() {
		var got []tun.Event
		for ev := range vt.Events() {
			got = append(got, ev)
		}
		ch <- got
	}()
	return ch
}

// TestCloseTerminatesEventConsumer: a consumer ranging over Events exits once
// Close runs, and events accepted before the close are delivered first and in
// order. Under concurrent SendEvent floods the transition must neither panic on
// the closed channel nor deadlock, and a post-close send is a silent no-op.
func TestCloseTerminatesEventConsumer(t *testing.T) {
	vt := mustNew(t, Config{})
	vt.SendEvent(tun.EventDown)
	vt.SendEvent(tun.EventMTUUpdate)
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	vt.SendEvent(tun.EventUp) // after Close: no panic, no delivery
	select {
	case got := <-drainEvents(vt):
		if len(got) != 2 || got[0] != tun.EventDown || got[1] != tun.EventMTUUpdate {
			t.Fatalf("delivered after close = %v, want [down mtu_update]", got)
		}
	case <-timeout(t):
		t.Fatal("event consumer did not exit after Close")
	}

	for iter := 0; iter < 20; iter++ {
		vt, err := New(Config{})
		if err != nil {
			t.Fatalf("iteration %d: New: %v", iter, err)
		}
		done := drainEvents(vt)
		var senders sync.WaitGroup
		stop := make(chan struct{})
		for i := 0; i < 4; i++ {
			senders.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						vt.SendEvent(tun.EventMTUUpdate)
					}
				}
			})
		}
		closed := make(chan error, 1)
		go func() { closed <- vt.Close() }()
		select {
		case <-closed:
		case <-timeout(t):
			close(stop)
			senders.Wait()
			t.Fatalf("iteration %d: Close deadlocked behind concurrent SendEvent", iter)
		}
		close(stop)
		senders.Wait()
		select {
		case <-done:
		case <-timeout(t):
			t.Fatalf("iteration %d: consumer did not exit", iter)
		}
	}
}

// TestEventsClosePreservesPacketAccounting: closing the event channel must not
// change packet drop accounting, and the packet channels must stay open while the
// event channel closes — that asymmetry is what makes a racing packet sender
// panic-free and the upstream reader terminate.
func TestEventsClosePreservesPacketAccounting(t *testing.T) {
	vt := mustNew(t, Config{InboundCapacity: 4, OutboundCapacity: 4})
	if err := vt.InjectInbound([]byte{1}); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	if _, err := vt.Write([][]byte{{2}}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s := vt.Stats(); s.InboundShutdownDrops != 1 || s.OutboundShutdownDrops != 1 || s.DropsTotal != 2 {
		t.Fatalf("stats after Close = %+v, want 1/1 drained and 2 total drops", s)
	}
	// An open empty channel blocks; a closed one reports ok=false at once.
	for name, ch := range map[string]<-chan []byte{"inbound": vt.Inbound(), "outbound": vt.Outbound()} {
		select {
		case _, ok := <-ch:
			t.Fatalf("%s channel closed=%v after Close; it must stay open and empty", name, !ok)
		case <-time.After(20 * time.Millisecond):
		}
	}
	// An open event channel would block here: that hang IS the pre-fix defect,
	// so it must fail on the bound instead.
	select {
	case _, ok := <-vt.Events():
		if ok {
			t.Fatal("event channel delivered a value after Close and is still open")
		}
	case <-timeout(t):
		t.Fatal("event channel still open after Close; the reader could not exit")
	}
}
