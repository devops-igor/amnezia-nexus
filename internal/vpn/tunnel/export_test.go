package tunnel

import "time"

// SetCreatedAtForTest overrides the device creation timestamp for testing.
func (d *AWGClientDevice) SetCreatedAtForTest(t time.Time) {
	d.createdAt = t
}

// SetLastHandshakeTimeForTest overrides LastHandshakeTime for testing.
func (d *AWGClientDevice) SetLastHandshakeTimeForTest(fn func() time.Time) {
	d.handshakeTimeFn = fn
}

// InPacketsForTest returns the inbound packet queue for testing verification.
func (d *AWGClientDevice) InPacketsForTest() <-chan []byte {
	if d.vtun == nil {
		return nil
	}
	return d.vtun.Inbound()
}

// SimulateDropsForTest increments the VirtualTUN drop counter for testing telemetry.
func (d *AWGClientDevice) SimulateDropsForTest(n uint64) {
	if d.vtun != nil {
		d.vtun.RecordDropN(n)
	}
}

// BuildAWGIPCConfigForTest exposes buildAWGIPCConfig for tests asserting
// obfuscation parameter handling in the rendered IPC config.
func BuildAWGIPCConfigForTest(privateKeyHex, publicKeyHex, endpoint string, awgParams map[string]any) string {
	return buildAWGIPCConfig(privateKeyHex, publicKeyHex, endpoint, awgParams)
}
