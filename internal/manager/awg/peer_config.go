package awg

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type wgShowPeerStat struct {
	LatestHandshake   string
	DataReceived      string
	DataSent          string
	DataReceivedBytes int64
	DataSentBytes     int64
	AllowedIPs        string
}

func parseWGShow(out string) map[string]wgShowPeerStat {
	stats := make(map[string]wgShowPeerStat)
	var currentPeer string
	var currentStat wgShowPeerStat

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "peer:") {
			if currentPeer != "" {
				stats[currentPeer] = currentStat
			}
			currentPeer = strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			currentStat = wgShowPeerStat{}
		} else if currentPeer != "" && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "latest handshake":
				currentStat.LatestHandshake = v
			case "transfer":
				tfParts := strings.Split(v, ",")
				if len(tfParts) == 2 {
					rx := strings.TrimSpace(strings.TrimSuffix(tfParts[0], "received"))
					tx := strings.TrimSpace(strings.TrimSuffix(tfParts[1], "sent"))
					currentStat.DataReceived = rx
					currentStat.DataSent = tx
					currentStat.DataReceivedBytes = parseSizeHuman(rx)
					currentStat.DataSentBytes = parseSizeHuman(tx)
				}
			case "allowed ips":
				currentStat.AllowedIPs = v
			}
		}
	}
	if currentPeer != "" {
		stats[currentPeer] = currentStat
	}
	return stats
}

func parseSizeHuman(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	mult := int64(1)
	switch strings.ToLower(parts[1]) {
	case "kib", "kb":
		mult = 1024
	case "mib", "mb":
		mult = 1024 * 1024
	case "gib", "gb":
		mult = 1024 * 1024 * 1024
	case "tib", "tb":
		mult = 1024 * 1024 * 1024 * 1024
	}
	return int64(val * float64(mult))
}

// upsertPeerInConfig replaces the [Peer] section whose PublicKey matches
// peerSection's PublicKey, or appends the section when no such peer exists.
// [Peer] blocks whose PublicKey is listed in removePubKeys are dropped (stale
// identity that was re-keyed under the same client name). Duplicate blocks for
// the same PublicKey are collapsed. Non-peer content is preserved as-is.
func upsertPeerInConfig(confText, peerSection string, removePubKeys ...string) (string, error) {
	confText = EnsureInterfaceTableOff(confText)
	peerLines := strings.Split(strings.TrimSpace(peerSection), "\n")
	newPub := ""
	for _, line := range peerLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PublicKey = ") {
			newPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
			break
		}
	}
	if newPub == "" {
		return "", errors.New("peer section is missing a PublicKey line")
	}

	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string
	replaced := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			line := lines[i]
			if strings.TrimSpace(line) == "" && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
				continue
			}
			out = append(out, line)
			continue
		}
		// Collect the whole [Peer] block (up to the next section header).
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		blockPub := ""
		for _, bl := range block {
			trimmed := strings.TrimSpace(bl)
			if strings.HasPrefix(trimmed, "PublicKey = ") {
				blockPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
				break
			}
		}
		stale := false
		for _, rk := range removePubKeys {
			if rk != "" && rk != newPub && rk == blockPub {
				stale = true
				break
			}
		}
		switch {
		case stale:
			if !replaced {
				out = append(out, peerLines...)
				replaced = true
			}
		case blockPub == newPub:
			if !replaced {
				out = append(out, peerLines...)
				replaced = true
			}
			// Duplicate legacy block for the same key: drop it.
		default:
			out = append(out, block...)
		}
		i = j - 1
	}
	if !replaced {
		// Blank separator line before the appended peer, mirroring the
		// formatting awg-quick conf files get from the portal.
		var withSep []string
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			withSep = append(withSep, "")
		}
		withSep = append(withSep, peerLines...)
		out = append(out, withSep...)
	}
	return strings.Join(out, "\n") + "\n", nil
}

// peerSectionFor renders the [Peer] section to append to the server config.
// Probe peers carry no PresharedKey line: the prober probes with psk="", so
// both sides must derive IKpsk2 keys with a zero PSK.
func peerSectionFor(isProbePeer bool, clientPubKey, psk, clientIP, allowedIPs string) string {
	if isProbePeer {
		if allowedIPs == "" {
			allowedIPs = clientIP + "/32"
		}
		return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", clientPubKey, allowedIPs)
	}
	return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientPubKey, psk, clientIP)
}

func extractPeerSection(confText, pubKey, ip string) string {
	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var targetIP net.IP
	if ip != "" {
		targetIP = net.ParseIP(strings.TrimSpace(ip))
	}

	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		match := false

		if pubKey != "" {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "PublicKey = ") {
					if strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = ")) == pubKey {
						match = true
						break
					}
				}
			}
		}
		if !match && targetIP != nil {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "AllowedIPs = ") {
					rawIPs := strings.TrimSpace(strings.TrimPrefix(trimmed, "AllowedIPs = "))
					for _, part := range strings.Split(rawIPs, ",") {
						part = strings.TrimSpace(part)
						if part == "" {
							continue
						}
						parsedIP, _, err := net.ParseCIDR(part)
						if err != nil {
							parsedIP = net.ParseIP(part)
						}
						if parsedIP != nil && parsedIP.Equal(targetIP) {
							match = true
							break
						}
					}
					if match {
						break
					}
				}
			}
		}

		if match {
			return strings.Join(block, "\n")
		}
		i = j - 1
	}
	return ""
}

func removePeerFromConfig(confText, pubKey, ip string) string {
	confText = EnsureInterfaceTableOff(confText)
	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string

	var targetIP net.IP
	if ip != "" {
		targetIP = net.ParseIP(strings.TrimSpace(ip))
	}

	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			out = append(out, lines[i])
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		match := false

		if pubKey != "" {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "PublicKey = ") {
					if strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = ")) == pubKey {
						match = true
						break
					}
				}
			}
		} else if targetIP != nil {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "AllowedIPs = ") {
					rawIPs := strings.TrimSpace(strings.TrimPrefix(trimmed, "AllowedIPs = "))
					for _, part := range strings.Split(rawIPs, ",") {
						part = strings.TrimSpace(part)
						if part == "" {
							continue
						}
						parsedIP, _, err := net.ParseCIDR(part)
						if err != nil {
							parsedIP = net.ParseIP(part)
						}
						if parsedIP != nil && parsedIP.Equal(targetIP) {
							match = true
							break
						}
					}
					if match {
						break
					}
				}
			}
		}

		if !match {
			out = append(out, block...)
		}
		i = j - 1
	}
	return strings.Join(out, "\n") + "\n"
}
