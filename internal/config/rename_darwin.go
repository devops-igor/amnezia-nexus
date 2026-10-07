//go:build darwin

package config

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func renameNoReplace(src, dst string) error {
	return unix.RenamexNp(src, dst, unix.RENAME_EXCL)
}

func isErrExist(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST)
}
