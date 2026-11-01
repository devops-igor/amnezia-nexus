package naive

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// NaiveClient holds the basic-auth credentials for a single NaiveProxy user.
//
//nolint:revive
type NaiveClient struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenerateNaiveCredentials creates a random username and secure password.
func GenerateNaiveCredentials() (user, pass string, err error) {
	uBytes := make([]byte, 6)
	if _, err := rand.Read(uBytes); err != nil {
		return "", "", fmt.Errorf("read random user bytes: %w", err)
	}
	pBytes := make([]byte, 16)
	if _, err := rand.Read(pBytes); err != nil {
		return "", "", fmt.Errorf("read random pass bytes: %w", err)
	}
	user = fmt.Sprintf("user_%s", hex.EncodeToString(uBytes))
	pass = hex.EncodeToString(pBytes)
	return user, pass, nil
}

// isTestDomainOrIP returns true if domain is an IP address, localhost, or a test domain (e.g. *.example.com).
func isTestDomainOrIP(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	if host, _, err := net.SplitHostPort(d); err == nil && host != "" {
		d = host
	}
	d = strings.Trim(d, "[]")
	if d == "" {
		return true
	}
	if net.ParseIP(d) != nil {
		return true
	}
	if d == "localhost" || strings.HasSuffix(d, ".localhost") || strings.HasSuffix(d, ".local") {
		return true
	}
	for _, reserved := range []string{"example.com", "example.net", "example.org"} {
		if d == reserved || strings.HasSuffix(d, "."+reserved) {
			return true
		}
	}
	for _, tld := range []string{".test", ".example", ".invalid", ".internal"} {
		if strings.HasSuffix(d, tld) {
			return true
		}
	}
	return false
}

// RenderCaddyfile generates a Caddyfile with forward_proxy, decoy website, and basic-auth credentials.
// Per audit guidance, { admin off } is omitted so caddy reload communicates over loopback 127.0.0.1:2019.
func RenderCaddyfile(port int, domain string, clients []NaiveClient) string {
	if port <= 0 {
		port = 443
	}
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	if host, _, err := net.SplitHostPort(domain); err == nil && host != "" {
		domain = host
	}
	domain = strings.Trim(domain, "[]")
	if domain == "" || domain == ":443" || domain == "443" {
		domain = "localhost"
	}

	var sb strings.Builder
	// Global options: enable loopback admin for caddy reload, fallback SNI for raw IP probes,
	// and restrict protocols to h1/h2 to eliminate HTTP/3 QUIC exposure on UDP 443.
	sb.WriteString("{\n")
	sb.WriteString("    admin 127.0.0.1:2019\n")
	fmt.Fprintf(&sb, "    default_sni %s\n", domain)
	fmt.Fprintf(&sb, "    fallback_sni %s\n", domain)
	sb.WriteString("    servers {\n")
	sb.WriteString("        protocols h1 h2\n")
	sb.WriteString("    }\n")
	sb.WriteString("}\n\n")

	// Hostless listener combined with domain ensures arbitrary destination CONNECT requests are accepted
	if port > 0 && port != 443 {
		fmt.Fprintf(&sb, ":%d, %s:%d {\n", port, domain, port)
	} else {
		fmt.Fprintf(&sb, ":443, %s {\n", domain)
	}

	if isTestDomainOrIP(domain) {
		sb.WriteString("    tls internal\n")
	}

	sb.WriteString("    header {\n")
	sb.WriteString("        -Server\n")
	sb.WriteString("        -Alt-Svc\n")
	sb.WriteString("    }\n")

	sb.WriteString("    handle_errors {\n")
	sb.WriteString("        header {\n")
	sb.WriteString("            -Server\n")
	sb.WriteString("            -Alt-Svc\n")
	sb.WriteString("        }\n")
	sb.WriteString("        respond \"{err.status_code} {err.status_text}\" {err.status_code}\n")
	sb.WriteString("    }\n")

	sb.WriteString("    route {\n")
	sb.WriteString("        @rawProbe {\n")
	sb.WriteString("            not method CONNECT\n")
	fmt.Fprintf(&sb, "            not host %s\n", domain)
	sb.WriteString("        }\n")
	sb.WriteString("        handle @rawProbe {\n")
	sb.WriteString("            respond \"Not Found\" 404 {\n")
	sb.WriteString("                close\n")
	sb.WriteString("            }\n")
	sb.WriteString("        }\n")

	validClients := make([]NaiveClient, 0, len(clients))
	for _, c := range clients {
		if c.Username != "" && c.Password != "" {
			validClients = append(validClients, c)
		}
	}

	if len(validClients) > 0 {
		sb.WriteString("        forward_proxy {\n")
		for _, c := range validClients {
			fmt.Fprintf(&sb, "            basic_auth %s %s\n", c.Username, c.Password)
		}
		sb.WriteString("            hide_ip\n")
		sb.WriteString("            hide_via\n")
		sb.WriteString("            probe_resistance\n")
		sb.WriteString("        }\n")
	}
	sb.WriteString("        root * /srv\n")
	sb.WriteString("        file_server\n")
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

// validateCaddyfileTokens rejects unterminated quoted tokens while ignoring comments.
func validateCaddyfileTokens(content string) error {
	var quote byte
	escaped := false
	for i := 0; i < len(content); i++ {
		c := content[i]
		if quote != 0 {
			if quote != '`' && escaped {
				escaped = false
				continue
			}
			if quote != '`' && c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '#' {
			for i+1 < len(content) && content[i+1] != '\n' {
				i++
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
		}
	}
	if quote != 0 {
		return fmt.Errorf("caddyfile contains unterminated %c quote", quote)
	}
	return nil
}

// parseSiteAddress extracts the host and port from a site header such as ":443, vpn.example.com".
// The port defaults to 443 and the host to empty when the header does not state them.
func parseSiteAddress(header string) (domain string, port int) {
	port = 443
	for _, seg := range strings.Split(header, ",") {
		cleaned := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(seg), "https://"), "http://")
		if strings.HasPrefix(cleaned, ":") {
			if p, err := strconv.Atoi(strings.TrimPrefix(cleaned, ":")); err == nil && p > 0 {
				port = p
			}
		} else if host, pStr, err := net.SplitHostPort(cleaned); err == nil {
			if host != "" {
				domain = host
			}
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				port = p
			}
		} else if cleaned != "" {
			domain = cleaned
		}
	}
	return domain, port
}

// validateCaddyfileStructure ensures tokens and braces are well-formed.
func validateCaddyfileStructure(content string) error {
	if err := validateCaddyfileTokens(content); err != nil {
		return err
	}
	openBraces := strings.Count(content, "{")
	closeBraces := strings.Count(content, "}")
	if openBraces == 0 || closeBraces == 0 {
		return errors.New("caddyfile contains no configuration blocks")
	}
	if openBraces != closeBraces {
		return fmt.Errorf("caddyfile contains unmatched braces: %d '{' vs %d '}'", openBraces, closeBraces)
	}
	return nil
}

func parseTopLevelSite(trimmed string) string {
	if !strings.HasSuffix(trimmed, "{") {
		return ""
	}
	site := strings.TrimSpace(strings.TrimSuffix(trimmed, "{"))
	if strings.HasPrefix(site, "(") || strings.HasPrefix(site, "&(") {
		return "" // snippet or named-route definition, not a site
	}
	return site
}

func parseBasicAuthDirective(trimmed string) (*NaiveClient, error) {
	if !strings.HasPrefix(trimmed, "basic_auth") {
		return nil, nil
	}
	parts := strings.Fields(trimmed)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed basic_auth directive: %q", trimmed)
	}
	return &NaiveClient{Username: parts[1], Password: parts[2]}, nil
}

// ParseCaddyfile extracts the configured domain, port, and client basic-auth pairs from a Caddyfile.
func ParseCaddyfile(content string) (domain string, port int, clients []NaiveClient, err error) {
	trimmedContent := strings.TrimSpace(content)
	if trimmedContent == "" {
		return "", 0, nil, errors.New("empty caddyfile content")
	}
	if err := validateCaddyfileStructure(trimmedContent); err != nil {
		return "", 0, nil, err
	}

	lines := strings.Split(trimmedContent, "\n")
	clients = []NaiveClient{}

	// The managed listener is the top-level site block enclosing forward_proxy (or the first site
	// block when forward_proxy is absent, e.g. zero clients); nested directives and other sites are ignored.
	// shortcut: brace depth is counted per line, so braces inside quoted strings are not understood.
	depth, forwardSite, firstSite, fallbackSite, curSite := 0, "", "", "", ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, disabledMarker); ok && depth > 0 && forwardSite == "" && isProxyOpen(rest) {
			forwardSite = curSite // disabled forward_proxy still identifies the managed site
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if client, err := parseBasicAuthDirective(trimmed); err != nil {
			return "", 0, nil, err
		} else if client != nil {
			clients = append(clients, *client)
		}
		if depth == 0 {
			if site := parseTopLevelSite(trimmed); site != "" {
				curSite = site
				if fallbackSite == "" {
					fallbackSite = curSite
				}
				if d, _ := parseSiteAddress(curSite); d != "" && firstSite == "" {
					firstSite = curSite
				}
			}
		}
		if f := strings.Fields(trimmed); depth > 0 && forwardSite == "" && len(f) > 0 && f[0] == "forward_proxy" {
			forwardSite = curSite
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth <= 0 {
			depth, curSite = 0, ""
		}
	}
	if forwardSite == "" {
		if firstSite != "" {
			forwardSite = firstSite
		} else {
			forwardSite = fallbackSite
		}
	}

	domain, port = parseSiteAddress(forwardSite)
	return domain, port, clients, nil
}

// BuildNaiveURI constructs a standard client https:// URI for NaiveProxy.
func BuildNaiveURI(domain string, port int, user, pass, name string) (string, error) {
	if domain == "" {
		return "", errors.New("domain cannot be empty")
	}
	if user == "" || pass == "" {
		return "", errors.New("user and pass cannot be empty")
	}
	if port <= 0 {
		port = 443
	}

	hostPort := domain
	if port != 443 {
		hostPort = net.JoinHostPort(domain, strconv.Itoa(port))
	}

	u := url.URL{
		Scheme:   "https",
		User:     url.UserPassword(user, pass),
		Host:     hostPort,
		Fragment: name,
	}

	return u.String(), nil
}

// DefaultDecoyHTML returns an authentic-looking static business website for decoy camouflage.
func DefaultDecoyHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aura Creative Studio</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; color: #222; background: #fafafa; }
        header { background: #fff; padding: 2rem; border-bottom: 1px solid #eaeaea; text-align: center; }
        main { max-width: 800px; margin: 3rem auto; padding: 0 1.5rem; line-height: 1.6; }
        h1 { font-size: 2.2rem; margin-bottom: 0.5rem; }
        p { color: #555; font-size: 1.1rem; }
        footer { margin-top: 5rem; text-align: center; color: #999; font-size: 0.9rem; padding: 2rem; }
    </style>
</head>
<body>
    <header>
        <h1>Aura Creative Studio</h1>
        <p>Architectural Visualization & Brand Design</p>
    </header>
    <main>
        <h2>Crafting Digital Spaces</h2>
        <p>We blend art and technology to build memorable visual identities and immersive digital architecture.</p>
    </main>
    <footer>
    &copy; 2026 Aura Creative Studio. All rights reserved.
    </footer>
    </body>
    </html>
    `
}

// RenderCaddyDockerfile returns the multi-stage Dockerfile for Caddy with forwardproxy.
func RenderCaddyDockerfile() string {
	return `FROM caddy:builder AS builder
    RUN xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@c096d6a00cb28e019cc1995b04bdc6a9311d8024
    FROM caddy:alpine
    COPY --from=builder /usr/bin/caddy /usr/bin/caddy
    `
}
