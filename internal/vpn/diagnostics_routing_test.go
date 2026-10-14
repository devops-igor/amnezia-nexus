package vpn

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestCheckRoutingInvariants(t *testing.T) {
	// Create mock service
	svc := &Service{
		sessionMgr: nil, // empty sessions
	}

	// Case 1: Empty routes, empty sessions -> consistent
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	if !diag.IsConsistent {
		t.Errorf("expected consistent for empty sessions/routes, got inconsistencies: %v", diag.InconsistencyDetails)
	}

	// Case 2: Routes without session and without return path
	routes := []forwarder.RouteInfo{
		{
			PeerKey:          "peer-a",
			AssignedIP:       "10.100.0.2",
			BackendTunnelID:  0,
			HasReturnPath:    false,
			ReturnPathClosed: true,
		},
	}
	diag2 := checkRoutingInvariants(svc, routes, ReturnStatsSnapshot{}, 0)
	if diag2.IsConsistent {
		t.Errorf("expected inconsistency for route without session and without return")
	}
	// These two slices carry REDACTED peer keys: they are built by iterating
	// maps keyed by the raw key, and ingress.RedactKey is applied before they
	// reach the API (issue #424 round 5, item 1a). "peer-a" is 6 characters,
	// so RedactKey fully masks it.
	if len(diag2.RoutesWithoutSession) != 1 || diag2.RoutesWithoutSession[0] != "******" {
		t.Errorf("expected the redacted key in RoutesWithoutSession, got %v", diag2.RoutesWithoutSession)
	}
	if len(diag2.RoutesWithoutReturn) != 1 || diag2.RoutesWithoutReturn[0] != "******" {
		t.Errorf("expected the redacted key in RoutesWithoutReturn, got %v", diag2.RoutesWithoutReturn)
	}

	// Case 3: Duplicate IP across routes
	routesDup := []forwarder.RouteInfo{
		{
			PeerKey:         "peer-1",
			AssignedIP:      "10.100.0.3",
			BackendTunnelID: 1,
			HasReturnPath:   true,
		},
		{
			PeerKey:         "peer-2",
			AssignedIP:      "10.100.0.3",
			BackendTunnelID: 1,
			HasReturnPath:   true,
		},
	}
	diagDup := checkRoutingInvariants(svc, routesDup, ReturnStatsSnapshot{}, 0)
	if diagDup.IsConsistent {
		t.Errorf("expected inconsistency for duplicate IPs")
	}
	if len(diagDup.DuplicateIPs) != 1 || diagDup.DuplicateIPs[0] != "10.100.0.3" {
		t.Errorf("expected 10.100.0.3 in DuplicateIPs, got %v", diagDup.DuplicateIPs)
	}
}
