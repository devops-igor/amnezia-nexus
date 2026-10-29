package naive

import (
	"errors"
	"fmt"
	"strings"
)

// Caddyfile credential editing is line-based and touches only forward_proxy basic_auth lines,
// so operator-added directives, headers, comments and formatting survive client mutations.
// shortcut: one directive per line is assumed (as RenderCaddyfile and the config editor produce);
// upgrade to a real Caddyfile tokenizer if multi-directive lines must be supported.

func caddyIndent(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

func isBasicAuthLine(line string) bool {
	f := strings.Fields(line)
	return len(f) >= 3 && f[0] == "basic_auth"
}

// insertLines returns lines with block inserted at position at.
func insertLines(lines []string, at int, block ...string) []string {
	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:at]...)
	out = append(out, block...)
	return append(out, lines[at:]...)
}

// addCaddyBasicAuth inserts a basic_auth line for user/pass, creating the forward_proxy block
// (right after the route opener, so it precedes file_server) when the Caddyfile has none.
func addCaddyBasicAuth(content, user, pass string) (string, error) {
	lines := strings.Split(content, "\n")
	cred := func(indent string) string { return fmt.Sprintf("%sbasic_auth %s %s", indent, user, pass) }

	lastAuth, proxyOpen, routeOpen := -1, -1, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		f := strings.Fields(t)
		switch {
		case isBasicAuthLine(l):
			lastAuth = i
		case len(f) == 2 && f[0] == "forward_proxy" && f[1] == "{" && proxyOpen < 0:
			proxyOpen = i
		case len(f) == 2 && f[0] == "route" && f[1] == "{" && routeOpen < 0:
			routeOpen = i
		}
	}

	switch {
	case lastAuth >= 0:
		lines = insertLines(lines, lastAuth+1, cred(caddyIndent(lines[lastAuth])))
	case proxyOpen >= 0:
		lines = insertLines(lines, proxyOpen+1, cred(caddyIndent(lines[proxyOpen])+"    "))
	case routeOpen >= 0:
		in := caddyIndent(lines[routeOpen]) + "    "
		lines = insertLines(lines, routeOpen+1,
			in+"forward_proxy {", cred(in+"    "),
			in+"    hide_ip", in+"    hide_via", in+"    probe_resistance", in+"}")
	default:
		return "", errors.New("caddyfile has no forward_proxy or route block to add credentials to")
	}
	return strings.Join(lines, "\n"), nil
}

// removeCaddyBasicAuth deletes basic_auth lines for user. A forward_proxy block left without any
// credentials is removed entirely, because an auth-less forward_proxy is an open proxy.
func removeCaddyBasicAuth(content, user string) string {
	var lines []string
	removed := false
	for _, l := range strings.Split(content, "\n") {
		if f := strings.Fields(l); isBasicAuthLine(l) && f[1] == user {
			removed = true
			continue
		}
		lines = append(lines, l)
	}
	if !removed {
		return content
	}

	for i := 0; i < len(lines); i++ {
		if f := strings.Fields(lines[i]); len(f) != 2 || f[0] != "forward_proxy" || f[1] != "{" {
			continue
		}
		end, hasAuth := i, false
		for depth := 0; end < len(lines); end++ {
			hasAuth = hasAuth || isBasicAuthLine(lines[end])
			depth += strings.Count(lines[end], "{") - strings.Count(lines[end], "}")
			if depth <= 0 {
				break
			}
		}
		if !hasAuth && end < len(lines) {
			lines = append(lines[:i], lines[end+1:]...)
			i--
		}
	}
	return strings.Join(lines, "\n")
}
