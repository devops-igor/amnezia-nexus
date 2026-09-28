package clientawg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is an allowlist projection of upstream status. Private keys, preshared
// keys, header-protection keys and raw IPC output are never exposed.
type Status struct {
	PublicKey  string
	ListenPort int
	Peers      []PeerStatus
}

// PeerStatus contains public identity, authenticated roaming endpoint and traffic
// counters. A zero LastHandshake means no completed handshake was observed.
type PeerStatus struct {
	PublicKey                   string
	AllowedIP                   netip.Prefix
	Endpoint                    string
	LastHandshake               time.Time
	ReceiveBytes, TransmitBytes uint64
}

// Status returns public upstream state, serialized against peer changes/Close.
func (d *ClientAWGDevice) Status() (Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return Status{}, ErrClosed
	}
	raw, err := d.dev.IpcGet()
	if err != nil {
		return Status{}, errors.New("clientawg: cannot read upstream status")
	}
	status, err := parseStatus(raw)
	if err != nil {
		return Status{}, err
	}
	status.PublicKey = d.publicKey
	return status, nil
}

func parseStatus(raw string) (Status, error) {
	var status Status
	var current *PeerStatus
	var seconds, nanoseconds int64
	flush := func() {
		if current != nil {
			if seconds != 0 || nanoseconds != 0 {
				current.LastHandshake = time.Unix(seconds, nanoseconds)
			}
			status.Peers = append(status.Peers, *current)
		}
	}
	invalid := errors.New("clientawg: invalid upstream public status")
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			port, err := strconv.Atoi(value)
			if err != nil || port < 0 || port > 65535 {
				return Status{}, invalid
			}
			status.ListenPort = port
		case "public_key":
			flush()
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 {
				return Status{}, invalid
			}
			current = &PeerStatus{PublicKey: base64.StdEncoding.EncodeToString(decoded)}
			seconds, nanoseconds = 0, 0
		case "allowed_ip":
			if current == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return Status{}, invalid
			}
			current.AllowedIP = prefix
		case "endpoint":
			if current != nil {
				current.Endpoint = value
			}
		case "last_handshake_time_sec", "last_handshake_time_nsec":
			if current == nil {
				continue
			}
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return Status{}, invalid
			}
			if key == "last_handshake_time_sec" {
				seconds = n
			} else {
				nanoseconds = n
			}
		case "rx_bytes", "tx_bytes":
			if current == nil {
				continue
			}
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return Status{}, invalid
			}
			if key == "rx_bytes" {
				current.ReceiveBytes = n
			} else {
				current.TransmitBytes = n
			}
		}
	}
	flush()
	sort.Slice(status.Peers, func(i, j int) bool { return status.Peers[i].PublicKey < status.Peers[j].PublicKey })
	return status, nil
}
