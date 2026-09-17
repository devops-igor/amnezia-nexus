package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func TestEscapeShellArg(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "''"},
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's me", `'it'\''s me'`},
		{"$VAR and `calc`", `'$VAR and ` + "`calc`'"},
		{"'quoted'", `''\''quoted'\'''`},
		// Null byte sanitization tests
		{"hello\x00world", "'helloworld'"},
		{"\x00", "''"},
		{"\x00\x00\x00", "''"},
		{"\x00it's\x00", `'it'\''s'`},
	}

	for _, tt := range tests {
		got := EscapeShellArg(tt.input)
		if got != tt.expected {
			t.Errorf("EscapeShellArg(%q) = %q; expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestEscapeShellArg_ArgvRoundTrip(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple word", "hello"},
		{"spaces between words", "hello world foo bar"},
		{"multiple consecutive spaces", "hello    world"},
		{"tabs and newlines", "line1\nline2\twith\ttabs\n"},
		{"single quotes", "it's a 'quoted' string"},
		{"double quotes", `"hello" "world"`},
		{"nested mixed quotes", `'""'''"'''"`},
		{"dollar variable expansion", "$HOME $PATH ${USER} $1 $?"},
		{"command substitution dollar", "$(whoami) $(rm -rf /) $(cat /etc/passwd)"},
		{"command substitution backticks", "`whoami` `id` `cat /etc/shadow`"},
		{"shell metacharacters", "; | & && || ;;"},
		{"redirects", "> < >> 2>&1 | tee /tmp/evil"},
		{"globs and wildcards", "* ? [a-z] {a,b}"},
		{"parentheses and subshells", "(id) && (reboot)"},
		{"brackets and braces", "{1..10} [test]"},
		{"backslash escapes", `\n \t \\ \" \' \$`},
		{"unicode characters", "Мой телефон 📱 café 測試"},
		{"null byte sanitization", "prefix\x00suffix\x00test"},
		{"complex exploit payload", `'; rm -rf /; $(whoami); ` + "`reboot`" + `; echo "pwned" > /tmp/pwn; #`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			escaped := EscapeShellArg(tc.input)
			script := fmt.Sprintf(`set -- %s; printf "%%d\n" "$#"; for a in "$@"; do printf "%%s\0" "$a"; done`, escaped)
			cmd := exec.Command("sh", "-c", script)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("sh execution failed: %v, script: %s", err, script)
			}

			parts := bytes.SplitN(out, []byte("\n"), 2)
			if len(parts) < 2 {
				t.Fatalf("unexpected output format: %q", out)
			}
			argCount := string(parts[0])
			if argCount != "1" {
				t.Fatalf("expected exactly 1 argument after shell unpacking, got %s for input %q", argCount, tc.input)
			}

			unpackedArg := bytes.TrimSuffix(parts[1], []byte("\x00"))
			expected := []byte(strings.ReplaceAll(tc.input, "\x00", ""))
			if !bytes.Equal(unpackedArg, expected) {
				t.Fatalf("argument corrupted after shell unpacking: got %q, want %q", unpackedArg, expected)
			}
		})
	}
}

func TestCleanSudoCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sudo apt update", "apt update"},
		{"   sudo   docker ps", "docker ps"},
		{"sudo sudo systemctl restart", "systemctl restart"},
		{"echo sudo", "echo sudo"},
		{"ls -la", "ls -la"},
	}

	for _, tt := range tests {
		got := CleanSudoCommand(tt.input)
		if got != tt.expected {
			t.Errorf("CleanSudoCommand(%q) = %q; expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestFormatSudoCommand(t *testing.T) {
	// 1. Root user
	cmd, stdin := FormatSudoCommand("sudo docker ps", "pass", true)
	if cmd != "docker ps" || stdin != "" {
		t.Fatalf("expected direct command for root, got cmd=%q, stdin=%q", cmd, stdin)
	}

	// 2. Non-root with password
	cmd, stdin = FormatSudoCommand("apt-get update", "my'pass", false)
	if !strings.Contains(cmd, "sudo -S -p '' -- /bin/bash -c") || !strings.Contains(cmd, "'apt-get update'") {
		t.Fatalf("unexpected formatted cmd: %s", cmd)
	}
	if stdin != "my'pass\n" {
		t.Fatalf("expected stdin password, got %q", stdin)
	}

	// 3. Non-root without password
	cmd, stdin = FormatSudoCommand("apt-get update", "", false)
	if !strings.Contains(cmd, "sudo -n -p '' -- /bin/bash -c") {
		t.Fatalf("unexpected formatted cmd: %s", cmd)
	}
	if stdin != "" {
		t.Fatalf("expected empty stdin, got %q", stdin)
	}
}

func TestSafeBuffer(t *testing.T) {
	var buf SafeBuffer
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = buf.Write([]byte("data\n"))
		}()
	}

	wg.Wait()
	str := buf.String()
	count := strings.Count(str, "data\n")
	if count != 50 {
		t.Fatalf("expected 50 writes, got %d", count)
	}
}

func TestRunSession_NilClient(t *testing.T) {
	_, _, code, err := RunSession(context.Background(), nil, "echo 1", nil)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
	if code != -1 {
		t.Fatalf("expected exitCode -1, got %d", code)
	}
}

func TestRunSession_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, code, err := RunSession(ctx, nil, "echo 1", nil)
	if code != -1 {
		t.Fatalf("expected code -1, got %d", code)
	}
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}
