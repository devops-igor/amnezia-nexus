package gigahost

// Decoding of the single-server answer (GET /servers/{id}).
//
// The provider documents the answer as the usual envelope with the server inside a
// data ARRAY:
//
//	{"meta":{"status":200},"data":[{"srv_id":3523,"cust_id":19998,…}]}
//
// Two other shapes unambiguously name one server and are accepted as well: the
// envelope carrying the object directly ({"data":{…}}) and the bare object ({…}).
// Everything else is refused rather than guessed at, because this answer decides
// both whether a server exists and which account owns it.
//
// Refused, each for a stated reason:
//   - an empty data array or null data: the answer names no server;
//   - an entry without a usable server id: the answer cannot be matched to the
//     request;
//   - an entry naming a different server: a different server is not this one;
//   - the same server named twice: an ambiguous answer;
//   - data of any other JSON type, or a payload that is not an object.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// decodeServerDetail reads a single-server payload for serverID.
func decodeServerDetail(rawData []byte, serverID int64) (*ServerInfo, error) {
	if serverID <= 0 {
		return nil, fmt.Errorf("invalid server id %d", serverID)
	}
	trimmed := bytes.TrimSpace(rawData)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("answer is not a JSON object")
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("answer is not a JSON object: %w", err)
	}

	data := bytes.TrimSpace(envelope.Data)
	switch {
	case len(data) == 0:
		// No envelope field: the server may be the whole body.
		return serverFromDetailObject(trimmed, serverID)
	case bytes.Equal(data, []byte("null")):
		return nil, errors.New("answer carries no server: data is null")
	case data[0] == '[':
		return serverFromDetailArray(data, serverID)
	case data[0] == '{':
		return serverFromDetailObject(data, serverID)
	default:
		return nil, fmt.Errorf("answer carries no server: data is not an object or an array (%s)", firstBytes(data, 24))
	}
}

// serverFromDetailArray reads the documented data array.
func serverFromDetailArray(data []byte, serverID int64) (*ServerInfo, error) {
	var entries []ServerInfo
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("answer's data array does not hold servers: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("answer carries no server: data is an empty array")
	}
	var found *ServerInfo
	for i := range entries {
		switch {
		case entries[i].ID <= 0:
			return nil, fmt.Errorf("answer entry %d of %d carries no usable server id", i+1, len(entries))
		case entries[i].ID == serverID && found != nil:
			return nil, fmt.Errorf("answer names server %d twice", serverID)
		case entries[i].ID == serverID:
			found = &entries[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("answer does not name server %d", serverID)
	}
	return found, nil
}

// serverFromDetailObject reads a server object, from the envelope or the whole body.
func serverFromDetailObject(data []byte, serverID int64) (*ServerInfo, error) {
	var server ServerInfo
	if err := json.Unmarshal(data, &server); err != nil {
		return nil, fmt.Errorf("answer is not a server object: %w", err)
	}
	if server.ID <= 0 {
		return nil, errors.New("answer carries no usable server id")
	}
	if server.ID != serverID {
		return nil, fmt.Errorf("answer names server %d, not the one requested (%d)", server.ID, serverID)
	}
	return &server, nil
}

// firstBytes renders the beginning of an unexpected payload for the error, bounded
// so a large answer cannot flood a log.
func firstBytes(data []byte, limit int) string {
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "…"
}
