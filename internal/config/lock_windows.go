//go:build windows

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type processLock struct {
	file *os.File
}

// acquireProcessLock acquires an exclusive advisory cross-process lock on Windows
// using LockFileEx.
func acquireProcessLock(lockPath string) (*processLock, error) {
	// #nosec G304 G703 -- Lock file path is within clean data directory
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	var ov windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ov); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock file %s: %w", lockPath, err)
	}
	return &processLock{file: f}, nil
}

// Release unlocks and closes the lock file descriptor.
func (l *processLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	var ov windows.Overlapped
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &ov)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("failed to unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close lock file: %w", closeErr)
	}
	return nil
}
