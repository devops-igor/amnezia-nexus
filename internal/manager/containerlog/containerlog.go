// Package containerlog defines the docker logging configuration shared by the
// protocol container installers.
//
// A container's own log is the only record of what the engine did while a
// readiness probe was failing, and the readiness error embeds it as its
// "(logs: …)" tail. A logging driver that cannot be read turns that tail into a
// daemon refusal instead of the engine's output, and a failed install removes
// the container, so the evidence would be unrecoverable afterwards.
//
// The default is therefore a readable driver bounded by explicit size caps. The
// unreadable driver remains available, but only when an operator explicitly
// opts out of keeping a container log at all.
package containerlog

import "strings"

const (
	// Driver is the logging driver the installers request by default: docker's
	// json-file driver, the one that keeps the container's stdout and stderr
	// readable through `docker logs`.
	Driver = "json-file"

	// MaxSize bounds a single log file before it is rotated.
	MaxSize = "10m"

	// MaxFiles bounds how many rotated log files are kept per container, so a
	// chatty engine cannot fill the host disk.
	MaxFiles = "3"

	// DisableParam is the install parameter that opts a single install out of
	// the container log. Only an explicit true selects the unreadable driver.
	DisableParam = "disable_container_log"
)

// RunArgs returns the docker run flags that configure the container log, one
// flag per line with a trailing backslash so a caller can splice the result into
// a line-continued command.
//
// A disabled log gets no size caps: the none driver stores nothing to bound and
// rejects log options.
func RunArgs(disabled bool) string {
	if disabled {
		return "--log-driver none"
	}
	return strings.Join([]string{
		"--log-driver " + Driver,
		"--log-opt max-size=" + MaxSize,
		"--log-opt max-file=" + MaxFiles,
	}, " \\\n")
}
