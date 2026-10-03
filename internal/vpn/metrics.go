package vpn

import (
	"io"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// WriteMetrics exports Prometheus text. The HTTP adapter owns authorization;
// the snapshot never includes peers, backend IDs, addresses or secrets.
func (s *Service) WriteMetrics(w io.Writer) error {
	var f *forwarder.Forwarder
	if s != nil {
		s.mu.RLock()
		f = s.forwarder
		s.mu.RUnlock()
	}
	return f.WriteDurationMetrics(w)
}
