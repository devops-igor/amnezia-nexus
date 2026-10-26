package tunnel

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// jitterDuration computes a jittered duration within [0.8*base, 1.2*base]
// given a sample in [0.0, 1.0).
func jitterDuration(base time.Duration, sample float64) time.Duration {
	if base <= 0 {
		return base
	}
	if sample < 0 {
		sample = 0
	} else if sample >= 1.0 {
		sample = 0.9999999999999999
	}
	factor := 0.8 + 0.4*sample
	d := time.Duration(float64(base) * factor)
	if d <= 0 {
		return base
	}
	return d
}

func (hp *HealthProber) nextProbeInterval() time.Duration {
	hp.mu.RLock()
	interval := hp.cfg.Interval
	hp.mu.RUnlock()
	if interval <= 0 {
		interval = 10 * time.Second
	}
	// #nosec G404 -- cadence jitter does not require cryptographic randomness
	return jitterDuration(interval, rand.Float64())
}

func (hp *HealthProber) nextSelfHealingInterval() time.Duration {
	hp.mu.RLock()
	interval := hp.cfg.SelfHealingInterval
	hp.mu.RUnlock()
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	// #nosec G404 -- cadence jitter does not require cryptographic randomness
	return jitterDuration(interval, rand.Float64())
}

// ProbeAll probes all backend tunnels concurrently and updates their statuses.
func (hp *HealthProber) ProbeAll(ctx context.Context) map[int64]error {
	if hp.pool == nil {
		return nil
	}

	tunnels := hp.pool.ListTunnels()
	results := make(map[int64]error)
	var mu sync.Mutex
	var wg sync.WaitGroup

	hp.mu.RLock()
	multiProto := hp.multiProtocolEnabled
	hp.mu.RUnlock()

	for _, t := range tunnels {
		if !t.Enabled || t.Status == "disabled" {
			// Administratively disabled tunnels are excluded from ordinary
			// probing. Runtime health-disabled tunnels are recovered by the
			// dedicated self-healing sweep.
			continue
		}
		if !multiProto && models.NormalizeTunnelProtocol(t.Protocol) != models.ProtocolAWG {
			continue
		}
		tunnel := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := hp.ProbeTunnel(ctx, tunnel)
			mu.Lock()
			results[tunnel.ServerID] = err
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results
}

// Start launches the periodic background probing loop and self-healing sweep loop.
// It performs an initial probe sweep before waiting for the first interval.
func (hp *HealthProber) Start(ctx context.Context) {
	hp.start(ctx, true)
}

// StartAfterInitialProbe launches the background loops without an immediate
// probe sweep. Service.Start uses this after its synchronous startup health
// gate so failure counters are not consumed twice back-to-back.
func (hp *HealthProber) StartAfterInitialProbe(ctx context.Context) {
	hp.start(ctx, false)
}

func (hp *HealthProber) start(ctx context.Context, initialProbe bool) {
	hp.mu.Lock()
	if hp.running {
		hp.mu.Unlock()
		return
	}
	hp.running = true
	hp.stopCh = make(chan struct{})
	hp.mu.Unlock()

	hp.wg.Add(2)
	go hp.probingLoop(ctx, initialProbe)
	go hp.selfHealingLoop(ctx)
}

// Stop terminates the background prober.
func (hp *HealthProber) Stop() {
	hp.mu.Lock()
	if !hp.running {
		hp.mu.Unlock()
		return
	}
	hp.running = false
	close(hp.stopCh)
	hp.mu.Unlock()

	hp.wg.Wait()
}

// IsRunning returns true if the prober is running.
func (hp *HealthProber) IsRunning() bool {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.running
}

func (hp *HealthProber) probingLoop(ctx context.Context, initialProbe bool) {
	defer hp.wg.Done()

	if initialProbe {
		_ = hp.ProbeAll(ctx)
	}

	timer := time.NewTimer(hp.nextProbeInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hp.stopCh:
			return
		case <-timer.C:
			_ = hp.ProbeAll(ctx)
			timer.Reset(hp.nextProbeInterval())
		}
	}
}

func (hp *HealthProber) selfHealingLoop(ctx context.Context) {
	defer hp.wg.Done()

	timer := time.NewTimer(hp.nextSelfHealingInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hp.stopCh:
			return
		case <-timer.C:
			_ = hp.SelfHealSweep(ctx)
			timer.Reset(hp.nextSelfHealingInterval())
		}
	}
}
