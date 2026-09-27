//go:build !unix && !windows

package config

import (
	"os"
)

type processLock struct {
	file *os.File
}

// acquireProcessLock is a no-op fallback on platforms that are neither Unix nor Windows.
func acquireProcessLock(lockPath string) (*processLock, error) {
	return &processLock{}, nil
}

// Release is a no-op fallback on platforms that are neither Unix nor Windows.
func (l *processLock) Release() error {
	return nil
}
