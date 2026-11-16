package gatewaydns

import (
	"net/netip"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

const (
	maxCNAMEHops = 16
	maxRRsParsed = 256
)

// AnswerClassification is the observation path's interpretation of one DNS
// answer: the names it traverses, the terminal IPv4 records that could become
// evidence, and the minimum TTL. It is the single classification both the
// observation path and the read-only policy explanation use (issue #825, review
// finding HIGH-03): a second traversal would let the explanation accept answers
// the observation path rejects, so a destination could be explained from an
// answer that never becomes trusted evidence.
type AnswerClassification struct {
	// Valid reports whether the observation path would use this answer at all.
	// An answer that is not valid produces no evidence, whatever its records say.
	Valid bool
	// Reason names why an answer is unusable, for diagnostics. Empty when Valid.
	Reason string
	// Names are the canonical names the answer traverses, in order: the queried
	// name first, then each CNAME target.
	Names []string
	// Terminal is the last name in the chain; its A records are the answer.
	Terminal string
	// Addresses are the terminal A records that pass the evidence filter (native
	// public IPv4 only), deduplicated in answer order. Empty is a valid outcome:
	// the answer simply carries no usable address.
	Addresses []netip.Addr
	// MinTTL is the smallest TTL seen along the chain and its terminal records.
	MinTTL uint32
}

func validateEnvelope(req *mdns.Msg, resp *mdns.Msg) (mdns.Question, bool) {
	if req == nil || resp == nil || len(req.Question) == 0 {
		return mdns.Question{}, false
	}
	q := req.Question[0]
	if q.Qclass != mdns.ClassINET || q.Qtype != mdns.TypeA {
		return mdns.Question{}, false
	}
	if !resp.Response || resp.Opcode != mdns.OpcodeQuery || resp.Rcode != mdns.RcodeSuccess || resp.Truncated {
		return mdns.Question{}, false
	}
	if len(resp.Question) == 0 ||
		!strings.EqualFold(resp.Question[0].Name, q.Name) ||
		resp.Question[0].Qtype != q.Qtype ||
		resp.Question[0].Qclass != q.Qclass {
		return mdns.Question{}, false
	}
	if len(resp.Answer)+len(resp.Ns)+len(resp.Extra) > maxRRsParsed {
		return mdns.Question{}, false
	}
	return q, true
}

func traverseCNAME(resp *mdns.Msg, startName string, initialTTL uint32) ([]string, string, uint32, bool) {
	currentName := startName
	traversedNames := []string{currentName}
	visited := make(map[string]struct{}, maxCNAMEHops)
	minTTL := initialTTL

	for hop := 0; hop < maxCNAMEHops; hop++ {
		var cnames []*mdns.CNAME
		hasA := false

		for _, rr := range resp.Answer {
			if strings.EqualFold(rr.Header().Name, currentName) {
				switch r := rr.(type) {
				case *mdns.CNAME:
					cnames = append(cnames, r)
				case *mdns.A:
					hasA = true
				}
			}
		}

		if (len(cnames) > 0 && hasA) || len(cnames) > 1 {
			return nil, "", 0, false
		}

		if len(cnames) == 1 {
			norm := strings.ToLower(strings.TrimSuffix(currentName, "."))
			if _, exists := visited[norm]; exists {
				return nil, "", 0, false // Cycle
			}
			visited[norm] = struct{}{}

			cnameRR := cnames[0]
			if cnameRR.Hdr.Ttl < minTTL {
				minTTL = cnameRR.Hdr.Ttl
			}
			currentName = cnameRR.Target
			traversedNames = append(traversedNames, currentName)
			continue
		}

		return traversedNames, currentName, minTTL, true
	}

	return nil, "", 0, false
}

func findTerminalARecords(resp *mdns.Msg, terminalName string, currentMinTTL uint32) ([]*mdns.A, uint32) {
	var records []*mdns.A
	minTTL := currentMinTTL
	for _, rr := range resp.Answer {
		if strings.EqualFold(rr.Header().Name, terminalName) {
			if aRec, ok := rr.(*mdns.A); ok && aRec.Hdr.Class == mdns.ClassINET {
				records = append(records, aRec)
				if aRec.Hdr.Ttl < minTTL {
					minTTL = aRec.Hdr.Ttl
				}
			}
		}
	}
	return records, minTTL
}

// ClassifyAnswer applies the observation path's envelope validation, CNAME
// traversal and terminal-address filter to one query/answer pair.
//
// maxTTL supplies the TTL ceiling used when the answer itself carries none; it
// affects MinTTL only, never validity.
//
// The classification is read-only: it allocates its own slices and never touches
// a session cache, so a caller can use it for a diagnostic without publishing
// evidence. Names that do not normalize invalidate the answer, exactly as the
// observation path does, because it discards such an answer instead of recording
// evidence from part of it.
func ClassifyAnswer(req *mdns.Msg, resp *mdns.Msg, maxTTL time.Duration) AnswerClassification {
	q, ok := validateEnvelope(req, resp)
	if !ok {
		return AnswerClassification{Reason: "invalid DNS answer envelope"}
	}

	initialTTL := uint32(maxTTL.Seconds())
	if initialTTL == 0 {
		initialTTL = 3600
	}

	traversedNames, terminalName, minTTL, ok := traverseCNAME(resp, q.Name, initialTTL)
	if !ok {
		return AnswerClassification{Reason: "CNAME chain rejected (cycle, ambiguity or hop limit)"}
	}

	terminalARecords, minTTL := findTerminalARecords(resp, terminalName, minTTL)
	if len(terminalARecords) == 0 {
		// A valid answer without a terminal A record: the observation path records
		// nothing, and the name simply has no usable address.
		return AnswerClassification{Valid: true, Terminal: terminalName, MinTTL: minTTL}
	}

	names := make([]string, 0, len(traversedNames))
	for _, name := range traversedNames {
		canon, err := policy.NormalizeDomain(name)
		if err != nil {
			return AnswerClassification{Reason: "a traversed name does not normalize"}
		}
		names = append(names, canon)
	}

	return AnswerClassification{
		Valid:     true,
		Names:     names,
		Terminal:  terminalName,
		Addresses: evidenceAddresses(terminalARecords),
		MinTTL:    minTTL,
	}
}

// evidenceAddresses filters terminal records exactly as the observation path
// does: native IPv4 that passes the SSRF/public-address policy, deduplicated.
func evidenceAddresses(records []*mdns.A) []netip.Addr {
	out := make([]netip.Addr, 0, len(records))
	seen := make(map[netip.Addr]struct{}, len(records))
	for _, aRec := range records {
		ip, ok := netip.AddrFromSlice(aRec.A)
		if !ok || !ip.IsValid() || !ip.Is4() {
			continue
		}
		if err := policy.ValidateFetchIP(ip); err != nil {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func evaluateDomainRules(traversedNames []string, snapshot *policy.Snapshot) (bool, bool) {
	requiresProxy := false
	for _, name := range traversedNames {
		canon, err := policy.NormalizeDomain(name)
		if err != nil {
			return false, false // Normalization failed
		}
		if snapshot.MatchCanonicalDomain(canon) {
			requiresProxy = true
		}
	}
	return requiresProxy, true
}

func buildObservations(
	addresses []netip.Addr,
	requiresProxy bool,
	snapshot *policy.Snapshot,
	minTTL uint32,
	maxTTL time.Duration,
	recvTime time.Time,
) []policy.Observation {
	effectiveTTL := time.Duration(minTTL) * time.Second
	if effectiveTTL > maxTTL {
		effectiveTTL = maxTTL
	}
	expiresAt := recvTime.Add(effectiveTTL)

	var observations []policy.Observation
	for _, ip := range addresses {
		decision := policy.Direct
		if requiresProxy || snapshot.MatchIPv4(ip) {
			decision = policy.Proxy
		}
		if minTTL == 0 && decision != policy.Proxy {
			continue
		}
		observations = append(observations, policy.Observation{
			IP:        ip,
			Decision:  decision,
			ExpiresAt: expiresAt,
		})
	}
	return observations
}

// ObserveResponse evaluates a completed DNS response against the active policy snapshot
// and publishes client-scoped route evidence into the session cache.
func ObserveResponse(
	req *mdns.Msg,
	resp *mdns.Msg,
	snapshot *policy.Snapshot,
	session *policy.SessionCache,
	recvTime time.Time,
	maxTTL time.Duration,
) ([]policy.Observation, error) {
	if session == nil || snapshot == nil {
		return nil, nil
	}

	answer := ClassifyAnswer(req, resp, maxTTL)
	if !answer.Valid || len(answer.Addresses) == 0 {
		return nil, nil
	}

	requiresProxy, ok := evaluateDomainRules(answer.Names, snapshot)
	if !ok {
		return nil, nil
	}

	observations := buildObservations(answer.Addresses, requiresProxy, snapshot, answer.MinTTL, maxTTL, recvTime)
	if len(observations) == 0 {
		return nil, nil
	}

	err := session.Observe(snapshot.Generation(), observations, recvTime)
	return observations, err
}
