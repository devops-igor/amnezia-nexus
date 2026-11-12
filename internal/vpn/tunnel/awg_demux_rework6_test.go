package tunnel

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func TestAuditR5_AWGReturnDemux(t *testing.T) {
	vt, err := virtualtun.New(virtualtun.Config{Name: "audit-r5-demux", MTU: 1280, InboundCapacity: 8, OutboundCapacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	d := &AWGClientDevice{vtun: vt, doneCh: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1500)
		_, _ = d.Read(b)
	}()
	responder := make(chan struct{})
	go func() {
		defer close(responder)
		select {
		case req := <-vt.Inbound():
			reply := BuildCanaryICMPEchoReply(net.IP(req[16:20]), net.IP(req[12:16]), binary.BigEndian.Uint16(req[24:26]), binary.BigEndian.Uint16(req[26:28]))
			_, _ = vt.Write([][]byte{reply}, 0)
		case <-time.After(time.Second):
		}
	}()
	err = ProbePacketDevice(context.Background(), d, 200*time.Millisecond, "10.200.0.0/16")
	_ = d.Close()
	<-done
	<-responder
	if err != nil {
		t.Fatalf("real AWGClientDevice single-reader demux failed: %v", err)
	}
	t.Log("real AWGClientDevice Write/VirtualTUN/Read hook request-reply passed; crypto and remote forwarding not part of this component fixture")
}
