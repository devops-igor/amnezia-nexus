package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// Coupled producer→API control for the PROXY return direction (issue #861, R18).
//
// The chain is the real one: a client packet is decided PROXY, the backend's answer is
// handed to RouteBackendToClient, the client pump writes it to the controlled client
// writer, and the admitting flow's evidence is read through the real diagnosis service.

func TestClientDiagnosisReportsProxyReturnChain(t *testing.T) {
	f := newClientDiagFixture(t)
	f.fwd.StartPumps(context.Background())
	t.Cleanup(f.fwd.StopPumps)

	remote := netip.MustParseAddr("93.184.216.99")
	f.sendTCP(t, remote, 41300, 443)

	sessionID := f.sessionID(t)
	var flow ClientDiagnosisFlow
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow = findFlowEvidence(t, answer.Flows.Entries, remote.String(), 443)
		if flow.Forward.Packets == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if flow.Return.Evidence != "not_measured" {
		t.Errorf("return evidence before any reply = %q, want not_measured", flow.Return.Evidence)
	}

	// The backend answers the client's own tuple.
	reply := buildTestPBRTCPPacket(remote, f.clientIP, 443, 41300, []byte("answer"))
	if err := f.fwd.RouteBackendToClient(11, reply, f.clientIP.String()); err != nil {
		t.Fatalf("backend return refused: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow = findFlowEvidence(t, answer.Flows.Entries, remote.String(), 443)
		if flow.Return.Delivered > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if flow.Return.Evidence != "observed" {
		t.Fatalf("return evidence = %q, want observed after a matched reply", flow.Return.Evidence)
	}
	if flow.Return.Matched != 1 || flow.Return.Admitted != 1 || flow.Return.Delivered != 1 {
		t.Errorf("return chain = matched %d / admitted %d / delivered %d, want 1/1/1",
			flow.Return.Matched, flow.Return.Admitted, flow.Return.Delivered)
	}
	if flow.Return.Failed != 0 || flow.Return.Failure != "" {
		t.Errorf("return failed = %d (%q), want none", flow.Return.Failed, flow.Return.Failure)
	}
}
