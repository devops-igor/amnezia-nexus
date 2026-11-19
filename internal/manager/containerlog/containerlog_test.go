package containerlog

import (
	"strings"
	"testing"
)

// The pinned expectation lives here once, at the definition, so that a default
// revert to an unreadable driver fails in one place instead of every consumer
// restating the same literal.
const wantDefaultArgs = `--log-driver json-file \
--log-opt max-size=10m \
--log-opt max-file=3`

func TestRunArgsDefaultIsReadableAndCapped(t *testing.T) {
	got := RunArgs(false)
	if got != wantDefaultArgs {
		t.Fatalf("default container log args changed:\n got: %q\nwant: %q", got, wantDefaultArgs)
	}
	if strings.Contains(got, "none") {
		t.Fatalf("default container log must stay readable, got %q", got)
	}
	if !strings.Contains(got, "--log-driver "+Driver) {
		t.Fatalf("default must use the shared driver %q, got %q", Driver, got)
	}
	if !strings.Contains(got, "--log-opt max-size="+MaxSize) {
		t.Fatalf("default must cap the log size at %q, got %q", MaxSize, got)
	}
	if !strings.Contains(got, "--log-opt max-file="+MaxFiles) {
		t.Fatalf("default must cap the rotated files at %q, got %q", MaxFiles, got)
	}
}

func TestRunArgsExplicitOptOutDisablesLog(t *testing.T) {
	got := RunArgs(true)
	if got != "--log-driver none" {
		t.Fatalf("explicit opt-out must request the unreadable driver, got %q", got)
	}
	// The none driver stores nothing, so caps on it would be rejected or
	// meaningless.
	if strings.Contains(got, "--log-opt") {
		t.Fatalf("disabled log must not carry size caps, got %q", got)
	}
}

// Every line but the last must end with the continuation marker the installers'
// command templates rely on, or splicing the fragment breaks the command.
func TestRunArgsIsSplittableIntoAContinuedCommand(t *testing.T) {
	for name, args := range map[string]string{
		"default": RunArgs(false),
		"opt-out": RunArgs(true),
	} {
		lines := strings.Split(args, "\n")
		for i, line := range lines {
			if strings.HasSuffix(line, "\\") {
				if i == len(lines)-1 {
					t.Errorf("%s: last line must not continue: %q", name, args)
				}
				continue
			}
			if i != len(lines)-1 {
				t.Errorf("%s: line %d must end with a continuation marker: %q", name, i, line)
			}
			if strings.HasPrefix(line, "--log-") == false {
				t.Errorf("%s: line %d is not a docker log flag: %q", name, i, line)
			}
		}
	}
}
