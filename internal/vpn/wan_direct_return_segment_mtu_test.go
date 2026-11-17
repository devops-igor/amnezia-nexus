//go:build linux

package vpn

import (
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// TestReturnSegConstructionFacts pins the two numbers the return-path
// qualification depends on to their single definitions, so the fixture cannot
// drift away from the boundary it claims to measure:
//
//   - the client MTU the qualification compares every delivered packet against is
//     the deployment's plaintext MTU (virtualtun.DefaultMTU), which the ingress
//     engine configures the portal device with and which the direct WAN return
//     path splits replies to;
//   - the production client device really gates injection at exactly that value,
//     accepting a packet of that size and refusing one byte more.
func TestReturnSegConstructionFacts(t *testing.T) {
	if returnSegClientMTU != virtualtun.DefaultMTU {
		t.Fatalf("qualification client MTU %d differs from the deployment plaintext MTU %d",
			returnSegClientMTU, virtualtun.DefaultMTU)
	}

	privateKey, publicKey := engineKeys(t)
	portal, err := clientawg.NewDevice(clientawg.Config{
		PrivateKey: privateKey, PublicKey: publicKey,
		TUN: virtualtun.Config{Name: "returnseg-gate-bound", MTU: virtualtun.DefaultMTU},
	})
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	defer func() { _ = portal.Close() }()

	atLimit := make([]byte, virtualtun.DefaultMTU)
	if err := portal.InjectInbound(atLimit); err != nil {
		t.Fatalf("the client device refused a %d byte packet, which is the MTU it is configured with: %v",
			len(atLimit), err)
	}
	overLimit := make([]byte, virtualtun.DefaultMTU+1)
	if err := portal.InjectInbound(overLimit); !errors.Is(err, clientawg.ErrPacketTooLarge) {
		t.Fatalf("the client device did not refuse a %d byte packet at its MTU gate: %v", len(overLimit), err)
	}
}
