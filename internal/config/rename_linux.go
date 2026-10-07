//go:build linux

package config

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace atomically renames src to dst without replacing dst if it already exists.
func renameNoReplace(src, dst string) error {
	return unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
}

// isErrExist checks if an error indicates that the target file already exists.
func isErrExist(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, unix.EEXIST)
}
