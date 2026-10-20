package models

import "fmt"

// DataPlaneI1Protocol returns the effective portal-client preamble protocol.
func (c *VPNConfig) DataPlaneI1Protocol() string {
	if c == nil || c.VPNDataPlaneI1Protocol == "" {
		return "sip"
	}
	return c.VPNDataPlaneI1Protocol
}

// ValidateDataPlaneI1Protocol rejects unsupported persisted or updated protocols.
func (c *VPNConfig) ValidateDataPlaneI1Protocol() error {
	switch c.DataPlaneI1Protocol() {
	case "sip", "dns":
		return nil
	default:
		return fmt.Errorf("invalid vpn_data_plane_i1_protocol %q: expected sip or dns", c.VPNDataPlaneI1Protocol)
	}
}
