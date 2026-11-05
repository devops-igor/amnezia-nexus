//go:build !linux

package vpn

import (
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// ValidateKernelPrerequisites returns an error on non-Linux platforms.
func ValidateKernelPrerequisites() error {
	return errors.New("vpn: kernel prerequisites only supported on Linux")
}

// NewProductionWANDevice creates a real Linux TUN device for production WAN egress.
func NewProductionWANDevice(name string) (forwarder.PacketDevice, error) {
	return nil, errors.New("vpn: production WAN device only supported on Linux")
}
