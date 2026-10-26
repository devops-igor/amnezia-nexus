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

// RenderCaddyfile generates a Caddyfile with forward_proxy, decoy website, and basic-auth credentials.
// Per audit guidance, { admin off } is omitted so caddy reload communicates over loopback 127.0.0.1:2019.
func RenderCaddyfile(port int, domain string, clients []NaiveClient) string {
	if port <= 0 {
		port = 443
	}
	if domain == "" {
		domain = "localhost"
	}

	var sb strings.Builder
	// Global options: enable loopback admin for caddy reload
	sb.WriteString("{\n")
	sb.WriteString("    admin 127.0.0.1:2019\n")
	sb.WriteString("}\n\n")

	// Domain and port block
	fmt.Fprintf(&sb, ":%d, %s {\n", port, domain)
	sb.WriteString("    route {\n")
	sb.WriteString("        forward_proxy {\n")

	for _, c := range clients {
		if c.Username != "" && c.Password != "" {
			fmt.Fprintf(&sb, "            basic_auth %s %s\n", c.Username, c.Password)
		}
	}

	sb.WriteString("            hide_ip\n")
	sb.WriteString("            hide_via\n")
	sb.WriteString("            probe_resistance\n")
	sb.WriteString("        }\n")
	sb.WriteString("        root * /srv\n")
	sb.WriteString("        file_server\n")
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

// ParseCaddyfile extracts the configured domain, port, and client basic-auth pairs from a Caddyfile.
func ParseCaddyfile(content string) (domain string, port int, clients []NaiveClient, err error) {
	lines := strings.Split(content, "\n")
	port = 443
	domain = ""
	clients = []NaiveClient{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "basic_auth ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				clients = append(clients, NaiveClient{
					Username: parts[1],
					Password: parts[2],
				})
			}
		} else if strings.Contains(trimmed, "{") && strings.Contains(trimmed, ":") {
			header := strings.TrimSuffix(trimmed, "{")
			header = strings.TrimSpace(header)
			segments := strings.Split(header, ",")
			for _, seg := range segments {
				seg = strings.TrimSpace(seg)
				if strings.HasPrefix(seg, ":") {
					pStr := strings.TrimPrefix(seg, ":")
					if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
						port = p
					}
				} else if seg != "" {
					domain = seg
				}
			}
		}
	}

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
