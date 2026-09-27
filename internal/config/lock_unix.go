//go:build unix

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type processLock struct {
	file *os.File
}

// acquireProcessLock acquires an exclusive advisory cross-process lock (flock)
// on the specified path with 0600 permissions.
func acquireProcessLock(lockPath string) (*processLock, error) {
	// #nosec G304 G703 -- Lock file path is within clean data directory
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to flock %s: %w", lockPath, err)
	}
	return &processLock{file: f}, nil
}

// Release unlocks and closes the lock file descriptor.
func (l *processLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("failed to unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close lock file: %w", closeErr)
	}
	return nil
}
