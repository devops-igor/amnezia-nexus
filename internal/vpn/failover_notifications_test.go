package vpn

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type recordingFailoverNotifier struct {
	outcomes []models.FailoverOutcome
}

func (r *recordingFailoverNotifier) NotifyFailoverOutcome(outcome models.FailoverOutcome) {
	r.outcomes = append(r.outcomes, outcome)
}

func TestNotifyFailoverOutcomeReachesRegisteredNotifier(t *testing.T) {
	service := &Service{}
	recorder := &recordingFailoverNotifier{}
	service.SetFailoverOutcomeNotifier(recorder)

	service.notifyFailoverOutcome(models.FailoverOutcome{
		SourceTunnelID: 4, Decision: "partial", Migrated: 1, Stranded: 2,
	})

	if len(recorder.outcomes) != 1 {
		t.Fatalf("notifier received %d outcomes, want 1", len(recorder.outcomes))
	}
	if recorder.outcomes[0].SourceTunnelID != 4 || recorder.outcomes[0].Stranded != 2 {
		t.Fatalf("outcome = %#v", recorder.outcomes[0])
	}
}

func TestNotifyFailoverOutcomeWithoutNotifierIsSafe(t *testing.T) {
	service := &Service{}
	service.notifyFailoverOutcome(models.FailoverOutcome{SourceTunnelID: 1, Decision: "success"})
	(*Service)(nil).notifyFailoverOutcome(models.FailoverOutcome{SourceTunnelID: 1})
}
