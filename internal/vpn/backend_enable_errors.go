package vpn

import (
	"errors"
	"fmt"
)

// BackendEnableError retains the underlying cause for errors.Is/As and server
// investigation, while Stage is a bounded, non-sensitive operation identifier.
type BackendEnableError struct {
	stage string
	cause error
}

func (e *BackendEnableError) Error() string {
	return fmt.Sprintf("backend enable %s: %v", e.stage, e.cause)
}
func (e *BackendEnableError) Unwrap() error { return e.cause }

// BackendEnableStage is safe for API failure metadata. It never parses error
// text or copies provider output, keys, addresses or paths into the response.
func BackendEnableStage(err error) string {
	var failure *BackendEnableError
	if errors.As(err, &failure) {
		return failure.stage
	}
	return "unknown"
}

func backendEnableFailure(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &BackendEnableError{stage: stage, cause: err}
}
