package awg

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestBuildAndRunAWGContainer_PortTakenFailsBeforePull verifies the install
// preflight: when the requested UDP port is already bound on the host (visible
// in `ss -lun` output) the installer must fail fast with a clear, actionable
// error BEFORE pulling the base image. Regression context (Issue #225): on
// Server 1 the panel container already bound UDP 51820, so `docker run` failed
// with "port is already allocated" only after a long pull+build cycle.
func TestBuildAndRunAWGContainer_PortTakenFailsBeforePull(t *testing.T) {
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "ss -lun") {
			return "udp   UNCONN 0      0           0.0.0.0:51820      0.0.0.0:*\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	err := buildAndRunAWGContainer(context.Background(), client, "51820")
	if err == nil {
		t.Fatalf("expected an error when the UDP port is already bound, got nil")
	}
	if !strings.Contains(err.Error(), "UDP port 51820 is already in use") {
		t.Errorf("expected clear 'already in use' error, got: %v", err)
	}
	for i, cmd := range commands {
		if strings.HasPrefix(cmd, "docker pull") {
			t.Errorf("docker pull ran at index %d before preflight failed; commands: %v", i, commands)
		}
	}
}

// TestBuildAndRunAWGContainer_PortTakenByDockerBindingFailsBeforePull covers
// the Server 1 scenario where the port is bound by another container: it does
// not show in `ss -lun` on the host network namespace, but `docker ps
// --format` output exposes it as `0.0.0.0:51820->51820/udp`.
func TestBuildAndRunAWGContainer_PortTakenByDockerBindingFailsBeforePull(t *testing.T) {
	client := newMockAWGSSHClient()
	var commands []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "ss -lun") {
			return "udp   UNCONN 0      0           127.0.0.1:53        0.0.0.0:*\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps") {
			return `0.0.0.0:51820->51820/udp
[::]:51820->51820/udp`, "", 0, nil
		}
		return "OK", "", 0, nil
	}

	err := buildAndRunAWGContainer(context.Background(), client, "51820")
	if err == nil {
		t.Fatalf("expected an error when the UDP port is bound by an existing docker container, got nil")
	}
	if !strings.Contains(err.Error(), "UDP port 51820 is already in use") {
		t.Errorf("expected clear 'already in use' error, got: %v", err)
	}
	for i, cmd := range commands {
		if strings.HasPrefix(cmd, "docker pull") {
			t.Errorf("docker pull ran at index %d before preflight failed; commands: %v", i, commands)
		}
	}
}

// TestBuildAndRunAWGContainer_FreePortPullsNewImage verifies the happy path on
// a free port: preflight passes, and the pull references the multiarch
// devopsigor/amneziawg base image required for ARM64 hosts (Issue #225).
func TestBuildAndRunAWGContainer_FreePortPullsNewImage(t *testing.T) {
	client := newMockAWGSSHClient()
	var commands []string
	var dockerfile string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "ss -lun") {
			return "udp   UNCONN 0      0           127.0.0.1:53        0.0.0.0:*\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps") {
			return "0.0.0.0:53->53/udp\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker build") {
			uploaded, ok := client.files["/opt/amnezia/amnezia-awg2/Dockerfile"]
			if !ok {
				return "", "Dockerfile missing", 1, nil
			}
			dockerfile = string(uploaded)
		}
		return "OK", "", 0, nil
	}

	if err := buildAndRunAWGContainer(context.Background(), client, "55424"); err != nil {
		t.Fatalf("buildAndRunAWGContainer failed on a free port: %v", err)
	}

	if !strings.Contains(dockerfile, "FROM "+awgBaseImage+"\n") {
		t.Errorf("Dockerfile must pin FROM %s, got:\n%s", awgBaseImage, dockerfile)
	}
	sawPull := false
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, "docker pull") {
			sawPull = true
			if !strings.Contains(cmd, "devopsigor/amneziawg") {
				t.Errorf("pull command must reference the multiarch devopsigor/amneziawg image, got: %s", cmd)
			}
			break
		}
	}
	if !sawPull {
		t.Errorf("expected an explicit docker pull command, got: %v", commands)
	}
}

// TestCheckUDPPortAvailable_ProbeErrorsAreNotFatal locks the fail-open
// contract: when the probe commands themselves fail (e.g. `ss` missing on the
// host), the preflight warns and continues instead of blocking the install —
// `docker run` stays the last-resort guard.
func TestCheckUDPPortAvailable_ProbeErrorsAreNotFatal(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "ss -lun") || strings.Contains(cmd, "docker ps") {
			return "", "command not found", 127, errors.New("exit status 127")
		}
		return "OK", "", 0, nil
	}

	if err := checkUDPPortAvailable(context.Background(), client, "51820"); err != nil {
		t.Fatalf("probe errors must not fail the preflight (fail-open design), got: %v", err)
	}
}

// TestCheckUDPPortAvailable unit-tests the preflight parser directly: ss -lun
// token matching plus docker ps binding patterns, including ports that share
// prefixes with bound ports (e.g. 5182 vs 51820) and the sanitized docker ps
// single-line fallback.
func TestCheckUDPPortAvailable(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		ssOut   string
		dpsOut  string
		wantErr bool
	}{
		{
			name:    "free_port",
			port:    "51820",
			ssOut:   "udp   UNCONN 0      0           127.0.0.1:53        0.0.0.0:*",
			dpsOut:  "",
			wantErr: false,
		},
		{
			name:    "bound_in_ss_exact_match",
			port:    "51820",
			ssOut:   "udp   UNCONN 0      0           0.0.0.0:51820      0.0.0.0:*",
			dpsOut:  "",
			wantErr: true,
		},
		{
			name:    "prefix_port_not_false_positive",
			port:    "5182",
			ssOut:   "udp   UNCONN 0      0           0.0.0.0:51820      0.0.0.0:*",
			dpsOut:  "",
			wantErr: false,
		},
		{
			name:    "docker_binding_udp",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:51820->51820/udp",
			wantErr: true,
		},
		{
			name:    "docker_binding_multiline_sanitized",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:53->53/udp, [::]:53->53/udp, 0.0.0.0:51820->51820/udp",
			wantErr: true,
		},
		{
			name:    "docker_binding_tcp_not_udp",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:51820->51820/tcp",
			wantErr: false,
		},
		{
			name:    "docker_binding_other_port",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:443->443/udp",
			wantErr: false,
		},
		{
			name:    "publish_filter_host_differs_from_container_port",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:51820->55424/udp",
			wantErr: true,
		},
		{
			name:    "publish_filter_range_includes_port",
			port:    "51821",
			ssOut:   "",
			dpsOut:  "0.0.0.0:51820-51830->51820-51830/udp",
			wantErr: true,
		},
		{
			name:    "tcp_binding_not_udp",
			port:    "51820",
			ssOut:   "",
			dpsOut:  "0.0.0.0:51820->51820/tcp",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "ss -lun") {
					return tt.ssOut, "", 0, nil
				}
				if strings.Contains(cmd, "docker ps") {
					return tt.dpsOut, "", 0, nil
				}
				return "OK", "", 0, nil
			}

			err := checkUDPPortAvailable(context.Background(), client, tt.port)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkUDPPortAvailable(port %s) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "UDP port "+tt.port+" is already in use") {
				t.Errorf("expected clear 'already in use' error, got: %v", err)
			}
		})
	}
}
