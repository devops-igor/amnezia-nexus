package vpn

import (
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// FailoverOutcomeNotifier receives the authoritative result of one failover
// attempt. It is called from the failover path and must not perform blocking I/O
// on the caller's goroutine: the data-plane owner may hold Service.mu.
type FailoverOutcomeNotifier interface {
	NotifyFailoverOutcome(outcome models.FailoverOutcome)
}

// SetFailoverOutcomeNotifier registers the optional Phase 5 notification
// producer. It is safe to call while the service is running.
func (s *Service) SetFailoverOutcomeNotifier(notifier FailoverOutcomeNotifier) {
	if s == nil {
		return
	}
	s.notifyMu.Lock()
	s.failoverNotifier = notifier
	s.notifyMu.Unlock()
}

func (s *Service) notifyFailoverOutcome(outcome models.FailoverOutcome) {
	if s == nil {
		return
	}
	s.notifyMu.RLock()
	notifier := s.failoverNotifier
	s.notifyMu.RUnlock()
	if notifier != nil {
		notifier.NotifyFailoverOutcome(outcome)
	}
}
