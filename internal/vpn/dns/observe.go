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
	records []*mdns.A,
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
	for _, aRec := range records {
		ip, ok := netip.AddrFromSlice(aRec.A)
		if !ok || !ip.IsValid() || !ip.Is4() {
			continue
		}
		if err := policy.ValidateFetchIP(ip); err != nil {
			continue
		}

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

	q, ok := validateEnvelope(req, resp)
	if !ok {
		return nil, nil
	}

	initialTTL := uint32(maxTTL.Seconds())
	if initialTTL == 0 {
		initialTTL = 3600
	}

	traversedNames, terminalName, minTTL, ok := traverseCNAME(resp, q.Name, initialTTL)
	if !ok {
		return nil, nil
	}

	terminalARecords, minTTL := findTerminalARecords(resp, terminalName, minTTL)
	if len(terminalARecords) == 0 {
		return nil, nil
	}

	requiresProxy, ok := evaluateDomainRules(traversedNames, snapshot)
	if !ok {
		return nil, nil
	}

	observations := buildObservations(terminalARecords, requiresProxy, snapshot, minTTL, maxTTL, recvTime)
	if len(observations) == 0 {
		return nil, nil
	}

	err := session.Observe(snapshot.Generation(), observations, recvTime)
	return observations, err
}
