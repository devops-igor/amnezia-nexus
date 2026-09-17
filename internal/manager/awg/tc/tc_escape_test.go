package tc

import (
	"strings"
	"testing"
)

// TestBuildBatchTCScript_MaliciousPeerIP verifies that a malicious peer IP
// cannot break out of the sh -c payload in BuildBatchTCScript. After the fix,
// the inner script is escaped as a single argument to sh -c, so shell
// metacharacters in peerIP are contained within the escaped argument and
// cannot execute as separate commands.
func TestBuildBatchTCScript_MaliciousPeerIP(t *testing.T) {
	// Use a valid IP that passes PeerToClassID. The test verifies the
	// structural escaping: the inner script must be a single escaped
	// argument to sh -c, not wrapped in brittle single quotes.
	peerIP := "10.0.0.50"

	clients := []map[string]any{
		{
			"clientIp": peerIP,
			"userData": map[string]any{
				"speed_limit_down": 10,
				"speed_limit_up":   5,
			},
		},
	}

	_, clientScript := BuildBatchTCScript("amnezia-awg", clients, nil, nil)

	if clientScript == "" {
		t.Fatal("expected non-empty client script for valid client data")
	}

	lines := strings.Split(clientScript, "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one line in client script")
	}

	cmd := lines[0]

	// Verify the command has the form: docker exec -i 'container' sh -c 'inner_script'
	if !strings.Contains(cmd, "docker exec -i ") {
		t.Fatalf("expected docker exec -i prefix, got: %s", cmd)
	}
	if !strings.Contains(cmd, " sh -c ") {
		t.Fatalf("expected sh -c in command, got: %s", cmd)
	}

	// The peer IP must appear inside the escaped sh -c argument.
	if !strings.Contains(cmd, peerIP) {
		t.Fatalf("peer IP not found in command: %s", cmd)
	}

	// Critical: verify that the sh -c argument is properly escaped.
	// After proper escaping, the inner script is wrapped in single quotes
	// by EscapeShellArg as a single argument.
	shCIndex := strings.Index(cmd, "sh -c ")
	if shCIndex < 0 {
		t.Fatalf("expected sh -c in command: %s", cmd)
	}
	argStart := shCIndex + len("sh -c ")
	if argStart >= len(cmd) {
		t.Fatalf("no argument after sh -c: %s", cmd)
	}
	// The argument should start with a single quote (from EscapeShellArg)
	if cmd[argStart] != '\'' {
		t.Fatalf("sh -c argument should start with single quote, got: %s", cmd[argStart:])
	}
	// The argument should end with a single quote
	if cmd[len(cmd)-1] != '\'' {
		t.Fatalf("sh -c argument should end with single quote, got: ...%s", cmd[len(cmd)-20:])
	}

	// Extract the escaped argument and verify it's properly delimited.
	escapedArg := cmd[argStart:]
	if !strings.HasPrefix(escapedArg, "'") || !strings.HasSuffix(escapedArg, "'") {
		t.Fatalf("escaped argument not properly quoted: %s", escapedArg)
	}

	// The tc commands should be inside the single-quoted region, and peerIP
	// must be escaped with ssh.EscapeShellArg within the inner script.
	if !strings.Contains(escapedArg, "tc class add dev") {
		t.Fatalf("inner tc command not found in escaped argument: %s", escapedArg)
	}
	if !strings.Contains(escapedArg, `match ip dst '\''10.0.0.50'\''/32`) {
		t.Fatalf("peer IP download filter not found in escaped argument: %s", escapedArg)
	}
	if !strings.Contains(escapedArg, `match ip src '\''10.0.0.50'\''/32`) {
		t.Fatalf("peer IP upload filter not found in escaped argument: %s", escapedArg)
	}
}

// TestBuildBatchTCScript_MaliciousClientIP verifies that malicious clientIp
// values with shell metacharacters (e.g. 10.0.0.$(id), 10.0.$(id).5) are
// rejected by PeerToClassID and completely omitted from the batch script.
func TestBuildBatchTCScript_MaliciousClientIP(t *testing.T) {
	maliciousIPs := []string{
		"10.0.0.$(id)",
		"10.0.$(id).5",
		"10.0.0.1; rm -rf /",
		"`reboot`",
		"::1",
		"invalid",
	}

	for _, malIP := range maliciousIPs {
		clients := []map[string]any{
			{
				"clientIp": malIP,
				"userData": map[string]any{
					"speed_limit_down": 10,
					"speed_limit_up":   5,
				},
			},
		}

		_, clientScript := BuildBatchTCScript("amnezia-awg", clients, nil, nil)
		if clientScript != "" {
			t.Fatalf("expected empty client script for malicious/invalid IP %q, got: %s", malIP, clientScript)
		}
	}
}

// TestBuildBatchTCScript_MaliciousContainerName verifies that a
// malicious peer IP with shell metacharacters is contained. Since PeerToClassID
// rejects non-numeric IPs, we test with a crafted container name to verify
// the escaping pattern holds. The key assertion is that the sh -c argument
// is a single properly-escaped token.
func TestBuildBatchTCScript_MaliciousContainerName(t *testing.T) {
	// A malicious container name with shell metacharacters
	malContainer := "amnezia; rm -rf /"

	clients := []map[string]any{
		{
			"clientIp": "10.0.0.50",
			"userData": map[string]any{
				"speed_limit_down": 10,
				"speed_limit_up":   5,
			},
		},
	}

	_, clientScript := BuildBatchTCScript(malContainer, clients, nil, nil)
	if clientScript == "" {
		t.Fatal("expected non-empty client script")
	}

	lines := strings.Split(clientScript, "\n")
	cmd := lines[0]

	// The malicious container name must be escaped — it should appear
	// as a single-quoted argument, not as raw text that could inject.
	// After EscapeShellArg, the semicolons and spaces are inside single quotes.
	shCIdx := strings.Index(cmd, "docker exec -i ")
	if shCIdx < 0 {
		t.Fatalf("expected docker exec -i: %s", cmd)
	}
	// After "docker exec -i " comes the escaped container name
	afterExec := cmd[shCIdx+len("docker exec -i "):]
	if !strings.HasPrefix(afterExec, "'") {
		t.Fatalf("container name should be escaped (start with quote): %s", afterExec)
	}

	// The escaped container name should end with a closing single quote
	// before " sh -c ". Verify the malicious content is inside quotes.
	// The command should be: docker exec -i 'amnezia; rm -rf /' sh -c '...'
	if !strings.Contains(cmd, "'amnezia; rm -rf /'") {
		t.Fatalf("malicious container name not properly escaped in command: %s", cmd)
	}

	// Verify the " sh -c " appears AFTER the escaped container name,
	// not inside it — meaning the container name didn't break out.
	shCPos := strings.Index(cmd, " sh -c ")
	if shCPos < 0 {
		t.Fatalf("expected sh -c after container name: %s", cmd)
	}
	// The container name escaping should end before sh -c
	execEnd := shCIdx + len("docker exec -i ")
	// Find the closing quote of the container name
	closeQuote := strings.Index(cmd[execEnd:], "' ")
	if closeQuote < 0 {
		t.Fatalf("container name not properly closed with quote: %s", cmd)
	}
	// The sh -c should come after the closing quote
	if shCPos < execEnd+closeQuote {
		t.Fatalf("sh -c appears inside escaped container name — breakout detected: %s", cmd)
	}
}

// TestBuildBatchTCScript_InfraScriptEscaping verifies that the infra commands
// use properly escaped sh -c arguments rather than brittle single-quote wrapping.
func TestBuildBatchTCScript_InfraScriptEscaping(t *testing.T) {
	infraScript, _ := BuildBatchTCScript("amnezia-awg", nil, nil, nil)
	if infraScript == "" {
		t.Fatal("expected non-empty infra script")
	}

	lines := strings.Split(infraScript, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "sh -c ") {
			t.Fatalf("line %d: expected sh -c in infra command: %s", i, line)
		}
		// Each sh -c argument should be escaped (start with single quote after "sh -c ")
		idx := strings.Index(line, "sh -c ")
		argPart := line[idx+len("sh -c "):]
		if !strings.HasPrefix(argPart, "'") {
			t.Errorf("line %d: sh -c argument should start with single quote: %s", i, line)
		}
		if !strings.HasSuffix(argPart, "'") {
			t.Errorf("line %d: sh -c argument should end with single quote: %s", i, line)
		}
	}
}
