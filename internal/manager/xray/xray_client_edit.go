package xray

import (
	"encoding/json"
	"errors"
	"fmt"
)

// editInboundClients applies edit to the settings.clients list of every inbound in cfgBytes and
// returns the re-marshaled config. Only the clients arrays are rewritten: every other key
// (routing, dns, policy, sniffing, custom per-client fields, ...) is carried over verbatim as raw JSON,
// so operator-edited configuration survives client mutations. Object key order is not preserved
// for the objects on the path to the clients list.
func editInboundClients(cfgBytes []byte, edit func(inbound int, clients []json.RawMessage) ([]json.RawMessage, error)) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(cfgBytes, &top); err != nil {
		return nil, fmt.Errorf("unmarshal xray config: %w", err)
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(top["inbounds"], &inbounds); err != nil {
		return nil, fmt.Errorf("unmarshal xray inbounds: %w", err)
	}
	for i, inbound := range inbounds {
		settings := map[string]json.RawMessage{}
		if raw, ok := inbound["settings"]; ok {
			if err := json.Unmarshal(raw, &settings); err != nil {
				return nil, fmt.Errorf("unmarshal inbound %d settings: %w", i, err)
			}
		}
		var clients []json.RawMessage
		if raw, ok := settings["clients"]; ok {
			if err := json.Unmarshal(raw, &clients); err != nil {
				return nil, fmt.Errorf("unmarshal inbound %d clients: %w", i, err)
			}
		}
		clients, err := edit(i, clients)
		if err != nil {
			return nil, err
		}
		if settings["clients"], err = json.Marshal(clients); err != nil {
			return nil, fmt.Errorf("marshal inbound %d clients: %w", i, err)
		}
		if inbound["settings"], err = json.Marshal(settings); err != nil {
			return nil, fmt.Errorf("marshal inbound %d settings: %w", i, err)
		}
	}
	var err error
	if top["inbounds"], err = json.Marshal(inbounds); err != nil {
		return nil, fmt.Errorf("marshal xray inbounds: %w", err)
	}
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal updated xray config: %w", err)
	}
	return out, nil
}

// appendInboundClient appends the client built for each inbound index to that inbound's clients list.
func appendInboundClient(cfgBytes []byte, clientFor func(inbound int) XrayClient) ([]byte, error) {
	return editInboundClients(cfgBytes, func(i int, clients []json.RawMessage) ([]json.RawMessage, error) {
		raw, err := json.Marshal(clientFor(i))
		if err != nil {
			return nil, fmt.Errorf("marshal new client: %w", err)
		}
		return append(clients, raw), nil
	})
}

// removeInboundClient drops every client whose id equals clientID from all inbounds.
func removeInboundClient(cfgBytes []byte, clientID string) ([]byte, error) {
	if clientID == "" {
		return nil, errors.New("clientID cannot be empty")
	}
	return editInboundClients(cfgBytes, func(_ int, clients []json.RawMessage) ([]json.RawMessage, error) {
		kept := make([]json.RawMessage, 0, len(clients))
		for _, raw := range clients {
			var c struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("unmarshal client: %w", err)
			}
			if c.ID != clientID {
				kept = append(kept, raw)
			}
		}
		return kept, nil
	})
}
