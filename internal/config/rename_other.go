//go:build !linux

package config

import (
	"errors"
	"os"
)

// renameNoReplace returns ErrUnsupported on non-Linux platforms where atomic no-replace
// rename is not implemented.
func renameNoReplace(src, dst string) error {
	return errors.ErrUnsupported
}

// isErrExist checks if an error indicates that the target file already exists.
func isErrExist(err error) bool {
	return errors.Is(err, os.ErrExist)
}
