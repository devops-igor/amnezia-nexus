package service

import (
	"context"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/service/reconciliation"
	"github.com/devops-igor/amnezia-nexus/internal/service/supervisor"
	"github.com/devops-igor/amnezia-nexus/internal/service/userops"
)

// BackgroundService defines the contract for periodic or persistent background workers.
type BackgroundService = supervisor.BackgroundService

// Supervisor coordinates background service lifecycles and recovery.
type Supervisor = supervisor.Supervisor

// NewSupervisor creates a new supervisor with default configuration.
func NewSupervisor(opts ...supervisor.Option) *Supervisor {
	return supervisor.New(opts...)
}

// Orchestrator coordinates scheduled periodic tasks.
type Orchestrator = orchestrator.Orchestrator

// NewOrchestrator creates a new BackgroundTaskOrchestrator.
func NewOrchestrator(db *database.DB, registry orchestrator.ProtocolResolver, opts ...orchestrator.Option) *Orchestrator {
	return orchestrator.New(db, registry, opts...)
}

// Reconciler coordinates startup and periodic protocol reconciliation.
type Reconciler = reconciliation.Reconciler
type ReconcilerOption = reconciliation.Option

// WithReconcilerInterval configures periodic reconciliation interval.
func WithReconcilerInterval(d time.Duration) ReconcilerOption {
	return reconciliation.WithInterval(d)
}

// WithReconcilerBootDelay configures initial delay before first background cleanup.
func WithReconcilerBootDelay(d time.Duration) ReconcilerOption {
	return reconciliation.WithBootDelay(d)
}

// NewReconciler creates a new Reconciler.
func NewReconciler(db *database.DB, registry reconciliation.ProtocolResolver, opts ...reconciliation.Option) *Reconciler {
	return reconciliation.New(db, registry, opts...)
}

// UserOpsService coordinates user mass operations.
type UserOpsService = userops.Service

// NewUserOpsService creates a new UserOpsService.
func NewUserOpsService(db *database.DB, registry userops.ProtocolResolver) *UserOpsService {
	return userops.NewUserOpsService(db, registry)
}

// MockBackgroundService provides a stub service for testing supervisor orchestration.
type MockBackgroundService struct {
	ServiceName string
	Interval    time.Duration
	stopCh      chan struct{}
}

// NewMockBackgroundService creates a test background service.
func NewMockBackgroundService(name string) *MockBackgroundService {
	return &MockBackgroundService{
		ServiceName: name,
		Interval:    10 * time.Millisecond,
		stopCh:      make(chan struct{}),
	}
}

func (m *MockBackgroundService) Name() string {
	return m.ServiceName
}

func (m *MockBackgroundService) Start(ctx context.Context) error {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.stopCh:
			return nil
		case <-ticker.C:
			// simulate periodic work
		}
	}
}

func (m *MockBackgroundService) Stop(ctx context.Context) error {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
	return nil
}
