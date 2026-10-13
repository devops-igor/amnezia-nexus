package vpn

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cpuTracker measures CPU usage via syscall.Getrusage.
type cpuTracker struct {
	mu           sync.Mutex
	lastWallTime time.Time
	lastUserTime time.Duration
	lastSysTime  time.Duration
	lastPercent  float64
}

var globalCPUTracker = &cpuTracker{}

func (ct *cpuTracker) Percent() float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return ct.lastPercent
	}

	userTime := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	sysTime := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	now := time.Now()

	if ct.lastWallTime.IsZero() {
		ct.lastWallTime = now
		ct.lastUserTime = userTime
		ct.lastSysTime = sysTime
		return 0.0
	}

	wallDelta := now.Sub(ct.lastWallTime).Seconds()
	if wallDelta < 0.2 {
		return ct.lastPercent
	}

	userDelta := (userTime - ct.lastUserTime).Seconds()
	sysDelta := (sysTime - ct.lastSysTime).Seconds()
	cpuDelta := userDelta + sysDelta

	numCPU := float64(runtime.NumCPU())
	if numCPU <= 0 {
		numCPU = 1.0
	}

	pct := (cpuDelta / wallDelta) * 100.0 / numCPU
	if pct < 0 {
		pct = 0
	} else if pct > 100.0 {
		pct = 100.0
	}

	ct.lastWallTime = now
	ct.lastUserTime = userTime
	ct.lastSysTime = sysTime
	ct.lastPercent = pct
	return pct
}

func getOpenFileDescriptors() (int, uint64) {
	var maxFD uint64 = 1024
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		maxFD = rLimit.Cur
	}

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, maxFD
	}
	return len(entries), maxFD
}

// getMemoryLimit reports a discovered finite cgroup capacity. An absent or
// unlimited cgroup is unknown; Go runtime Sys is not a memory capacity.
func getMemoryLimit() uint64 {
	return readMemoryLimit(os.ReadFile)
}

func readMemoryLimit(readFile func(string) ([]byte, error)) uint64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil && limit > 0 && limit < 1<<60 {
			return limit
		}
	}
	return 0
}

func collectRuntimeResources() RuntimeResources {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	openFD, maxFD := getOpenFileDescriptors()
	memLimit := getMemoryLimit()

	var memUsagePct float64
	if memLimit > 0 {
		memUsagePct = float64(m.Alloc) / float64(memLimit) * 100.0
		if memUsagePct > 100.0 {
			memUsagePct = 100.0
		}
	}

	// Calculate GC Pause p95
	var gcPauseP95MS float64
	if m.NumGC > 0 {
		n := int(m.NumGC)
		if n > 256 {
			n = 256
		}
		pauses := make([]uint64, 0, n)
		for i := 0; i < n; i++ {
			p := m.PauseNs[(int(m.NumGC)-1-i+256)%256]
			if p > 0 {
				pauses = append(pauses, p)
			}
		}
		if len(pauses) > 0 {
			sort.Slice(pauses, func(i, j int) bool { return pauses[i] < pauses[j] })
			idx := int(float64(len(pauses)-1) * 0.95)
			gcPauseP95MS = float64(pauses[idx]) / 1e6
		}
	}

	return RuntimeResources{
		CPUPercent:           globalCPUTracker.Percent(),
		MemoryAllocBytes:     m.Alloc,
		MemorySysBytes:       m.Sys,
		MemoryLimitBytes:     memLimit,
		MemoryLimitAvailable: memLimit > 0,
		MemoryUsagePct:       memUsagePct,
		Goroutines:           runtime.NumGoroutine(),
		GCPauseP95MS:         gcPauseP95MS,
		OpenFileDesc:         openFD,
		MaxFileDesc:          maxFD,
	}
}
