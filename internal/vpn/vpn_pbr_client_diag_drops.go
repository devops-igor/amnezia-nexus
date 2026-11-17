package vpn

import (
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// clientDiagnosisDropsSection renders the retained pre-flow refusals of the selected
// session.
//
// The rows are the producer's own aggregated records: reason, the tuple the packet
// actually carried, count, bytes and the first/last instants. A refusal that carried no
// tuple says so instead of showing an empty address. The coverage block states what the
// bounded ledger holds and what it evicted or pruned, so an empty page is never read as
// "this client was never refused".
func clientDiagnosisDropsSection(snap forwarder.DropSnapshot) ClientDiagnosisDrops {
	out := ClientDiagnosisDrops{
		Available: true,
		State:     "observed",
		Total:     snap.Total,
		Truncated: snap.Truncated,
		Entries:   make([]ClientDiagnosisDrop, 0, len(snap.Entries)),
		Coverage: ClientDiagnosisDropCoverage{
			StartedAt:       clientDiagnosisTime(snap.Coverage.StartedAt),
			Stored:          snap.Coverage.Stored,
			Merged:          snap.Coverage.Merged,
			Evicted:         snap.Coverage.Evicted,
			Pruned:          snap.Coverage.Pruned,
			Keys:            snap.Coverage.Keys,
			KeyLimit:        snap.SessionLimit,
			AgeLimitSeconds: int(forwarder.DropMaxAge.Seconds()),
		},
	}
	if snap.Total == 0 {
		out.State = "none_retained"
	}
	for _, rec := range snap.Entries {
		row := ClientDiagnosisDrop{
			Reason:    rec.Key.Reason,
			Count:     int64(rec.Count), // #nosec G115 -- bounded by the ledger's burst cap.
			Bytes:     rec.Bytes,
			FirstSeen: clientDiagnosisTime(rec.FirstSeen),
			LastSeen:  clientDiagnosisTime(rec.LastSeen),
		}
		if rec.Key.HasTuple {
			row.HasTuple = true
			row.DestinationIP = clientDiagnosisIPv4(rec.Key.DstIP)
			row.DestinationPort = rec.Key.DstPort
			row.Protocol = clientDiagnosisProtocol(rec.Key.Protocol)
		}
		out.Entries = append(out.Entries, row)
	}
	return out
}

// clientDiagnosisIPv4 renders the four recorded bytes without inventing a value when they
// were never observed.
func clientDiagnosisIPv4(raw [4]byte) string {
	if raw == [4]byte{} {
		return ""
	}
	return netip.AddrFrom4(raw).String()
}
