package awg

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestEscapeShellArg_VerifyQuoting verifies that EscapeShellArg properly
// single-quote-escapes arguments to prevent shell injection.
func TestEscapeShellArg_VerifyQuoting(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "''"},
		{"simple", "'simple'"},
		{"amnezia-awg2", "'amnezia-awg2'"},
		{"10.100.0.0/16", "'10.100.0.0/16'"},
		{"has'quote", "'has'\\''quote'"},
		{"evil;rm -rf /", "'evil;rm -rf /'"},
		{"$(whoami)", "'$(whoami)'"},
		{"`whoami`", "'`whoami`'"},
		{"with\x00null", "'withnull'"},
	}
	for _, tc := range tests {
		got := ssh.EscapeShellArg(tc.input)
		if got != tc.want {
			t.Errorf("EscapeShellArg(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestPrepareHostAndContainers_EscapesContainerNames verifies that container
// names interpolated into docker stop/rm commands are shell-escaped.
func TestPrepareHostAndContainers_EscapesContainerNames(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		return "", "", 0, nil
	}

	_ = prepareHostAndContainers(ctx, client)

	for _, cmd := range commands {
		if strings.Contains(cmd, "docker stop ") || strings.Contains(cmd, "docker rm ") {
			// Every container name in a docker stop/rm command must be single-quoted
			for _, name := range AWGContainerNames {
				if strings.Contains(cmd, "'"+name+"'") {
					// Good — escaped
				} else if strings.Contains(cmd, " "+name+" ") || strings.HasSuffix(cmd, " "+name) {
					t.Errorf("command has unescaped container name %q: %s", name, cmd)
				}
			}
		}
	}
}

// TestUninstall_EscapesContainerNames verifies that docker stop/rm/rmi commands
// in Uninstall use shell-escaped container names.
func TestUninstall_EscapesContainerNames(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	_ = mgr.Uninstall(ctx, server)

	for _, cmd := range commands {
		if strings.Contains(cmd, "docker stop ") || strings.Contains(cmd, "docker rm ") || strings.Contains(cmd, "docker rmi ") {
			for _, name := range AWGContainerNames {
				if strings.Contains(cmd, "'"+name+"'") {
					// Good — escaped
				} else if strings.Contains(cmd, " "+name+" ") || strings.HasSuffix(cmd, " "+name) {
					t.Errorf("command has unescaped container name %q: %s", name, cmd)
				}
			}
		}
	}
}

// TestEnsureBackendRoutingAndNAT_EscapesSubnet verifies that the subnet value
// in the host-level iptables rule is shell-escaped.
func TestEnsureBackendRoutingAndNAT_EscapesSubnet(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	_ = mgr.ensureBackendRoutingAndNAT(ctx, client, "10.100.0.0/16")

	// The host-level rule must have the subnet and bridge device shell-escaped
	for _, cmd := range commands {
		if strings.Contains(cmd, "iptables -t nat -C POSTROUTING -s") && strings.Contains(cmd, "! -o") {
			// Host-level rule: subnet and bridge device must be quoted
			if !strings.Contains(cmd, "'10.100.0.0/16'") {
				t.Errorf("host-level rule subnet not shell-escaped: %s", cmd)
			}
			if !strings.Contains(cmd, "'amn0'") && !strings.Contains(cmd, "'docker0'") {
				t.Errorf("host-level rule bridge device not shell-escaped: %s", cmd)
			}
		}
	}
}

// TestResolveContainerName_EscapesFilterCommand verifies that docker ps --filter
// commands use shell-escaped container names.
func TestResolveContainerName_EscapesFilterCommand(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "docker ps --filter name=^") && strings.Contains(cmd, "{{.Names}}") {
			for _, name := range AWGContainerNames {
				if strings.Contains(cmd, name) {
					return name + "\n", "", 0, nil
				}
			}
			return "amnezia-awg2\n", "", 0, nil
		}
		return "Up 5 hours\n", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	_ = mgr.resolveContainerName(ctx, client)

	for _, cmd := range commands {
		if strings.Contains(cmd, "docker ps --filter name=^") {
			// Container names in filter must be shell-escaped
			for _, name := range AWGContainerNames {
				if strings.Contains(cmd, "^'"+name+"'$") {
					// Good — escaped
				} else if strings.Contains(cmd, "^"+name+"$") {
					t.Errorf("docker ps filter has unescaped container name %q: %s", name, cmd)
				}
			}
		}
	}
}

// TestShellEscapedContainerNameInCommands verifies that container names in
// docker commands are shell-escaped AND that no unescaped shell metacharacters
// appear outside of single-quoted regions.
func TestShellEscapedContainerNameInCommands(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		return "", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	_ = mgr.buildAndRunAWGContainer(ctx, client, "55424")

	// Verify that container names in docker commands are shell-escaped
	for _, cmd := range commands {
		// docker pull should have escaped image name
		if strings.HasPrefix(cmd, "docker pull ") {
			if !strings.Contains(cmd, "'") {
				t.Errorf("docker pull command should have shell-escaped image name: %s", cmd)
			}
		}
		// docker build should have escaped container name
		if strings.Contains(cmd, "docker build") {
			if !strings.Contains(cmd, "'amnezia-awg2'") {
				t.Errorf("docker build command should have shell-escaped container name: %s", cmd)
			}
		}
		// docker run should have escaped port and container name
		if strings.Contains(cmd, "docker run -d") {
			if !strings.Contains(cmd, "'55424'") {
				t.Errorf("docker run command should have shell-escaped port: %s", cmd)
			}
		}
		// docker network connect should have escaped container name
		if strings.Contains(cmd, "docker network connect") {
			if !strings.Contains(cmd, "'amnezia-awg2'") {
				t.Errorf("docker network connect command should have shell-escaped container name: %s", cmd)
			}
		}
		// Structural check: no unescaped shell metacharacters (; | & $ `)
		// should appear outside single-quoted regions. This catches the
		// class of bugs where a value is interpolated raw.
		if hasUnescapedMetachar(cmd) {
			t.Errorf("command has unescaped shell metacharacter outside quotes: %s", cmd)
		}
	}
}

// hasUnescapedMetachar returns true if any of ; | & $ ` appear outside
// single-quoted regions in the command string. This is a structural check
// that catches shell injection even when specific values aren't known.
// It skips the legitimate "||" and "&&" operators that appear in command
// flow control (e.g., "cmd 2>/dev/null || true") by treating consecutive
// | or & as operators, not injection.
func hasUnescapedMetachar(cmd string) bool {
	inSingleQuote := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\'' {
			inSingleQuote = !inSingleQuote
			continue
		}
		if !inSingleQuote {
			switch c {
			case ';', '$', '`':
				return true
			case '|':
				// Skip legitimate "||" operator
				if i+1 < len(cmd) && cmd[i+1] == '|' {
					i++ // skip next |
					continue
				}
				return true
			case '&':
				// Skip legitimate "&&" operator
				if i+1 < len(cmd) && cmd[i+1] == '&' {
					i++ // skip next &
					continue
				}
				return true
			}
		}
	}
	return false
}
