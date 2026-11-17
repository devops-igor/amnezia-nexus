package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Coupled producer→API control for PROXY backend device-write completion
// (issue #861, R15/R16).
//
// The chain is the real one: a client packet is decided PROXY, admitted into the
// bounded backend queue, written by the pump to a backend device that refuses, and the
// admitting flow's evidence is then read through the real diagnosis service. Nothing
// here sets a counter by hand.

// refusingBackendDevice refuses every write.
type refusingBackendDevice struct{ writes int }

func (d *refusingBackendDevice) Read(_ []byte) (int, error) { return 0, nil }

func (d *refusingBackendDevice) Write(_ []byte) (int, error) {
	d.writes++
	return 0, errors.New("backend device write refused")
}

func (d *refusingBackendDevice) Close() error { return nil }

func TestClientDiagnosisReportsBackendWriteFailure(t *testing.T) {
	f := newClientDiagFixture(t)
	device := &refusingBackendDevice{}
	f.fwd.AttachBackendDevice(11, device)
	f.fwd.StartPumps(context.Background())
	t.Cleanup(f.fwd.StopPumps)

	// No DNS evidence for 8.8.4.4: the decision is the fail-closed PROXY default.
	f.sendTCP(t, netip.MustParseAddr("8.8.4.4"), 41300, 443)

	sessionID := f.sessionID(t)
	var flow ClientDiagnosisFlow
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow = findFlowEvidence(t, answer.Flows.Entries, "8.8.4.4", 443)
		if flow.Forward.BackendWriteFailed > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if flow.Dispatch.State != "queued_to_backend" {
		t.Errorf("dispatch = %+v, want the queue admission recorded separately", flow.Dispatch)
	}
	if flow.Forward.Packets != 1 {
		t.Errorf("admitted packets = %d, want the queue admission preserved on failure", flow.Forward.Packets)
	}
	if flow.Forward.BackendWrites != 0 {
		t.Errorf("device completions = %d, want 0 when the device refuses", flow.Forward.BackendWrites)
	}
	if flow.Forward.BackendWriteFailed != 1 {
		t.Fatalf("device failures = %d, want the refused write observed", flow.Forward.BackendWriteFailed)
	}
	if flow.Forward.BackendWriteFailure != forwarder.FlowBackendWriteFailed {
		t.Errorf("device failure token = %q, want %q", flow.Forward.BackendWriteFailure, forwarder.FlowBackendWriteFailed)
	}
}
