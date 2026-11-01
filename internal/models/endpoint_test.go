package models

import (
	"testing"
)

func TestEndpoint_ParsingAndFormatting(t *testing.T) {
	parseCases := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "valid bracketed ipv6",
			input:    "[2001:db8::10]:443",
			wantHost: "2001:db8::10",
			wantPort: "443",
			wantErr:  false,
		},
		{
			name:     "valid bracketed ipv6 with custom port",
			input:    "[2001:db8::10]:8443",
			wantHost: "2001:db8::10",
			wantPort: "8443",
			wantErr:  false,
		},
		{
			name:     "valid bracketed ipv6 loopback",
			input:    "[::1]:51820",
			wantHost: "::1",
			wantPort: "51820",
			wantErr:  false,
		},
		{
			name:     "valid ipv4",
			input:    "192.0.2.1:443",
			wantHost: "192.0.2.1",
			wantPort: "443",
			wantErr:  false,
		},
		{
			name:     "valid hostname",
			input:    "backend.example.com:443",
			wantHost: "backend.example.com",
			wantPort: "443",
			wantErr:  false,
		},
		{
			name:     "unbracketed ipv6 with port",
			input:    "2001:db8::10:443",
			wantHost: "",
			wantPort: "",
			wantErr:  true,
		},
		{
			name:     "missing port bracketed ipv6",
			input:    "[2001:db8::10]",
			wantHost: "",
			wantPort: "",
			wantErr:  true,
		},
		{
			name:     "empty endpoint",
			input:    "",
			wantHost: "",
			wantPort: "",
			wantErr:  true,
		},
	}

	for _, tc := range parseCases {
		t.Run("ParseEndpoint/"+tc.name, func(t *testing.T) {
			host, port, err := ParseEndpoint(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEndpoint(%q) err = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr {
				if host != tc.wantHost {
					t.Errorf("host = %q, want %q", host, tc.wantHost)
				}
				if port != tc.wantPort {
					t.Errorf("port = %q, want %q", port, tc.wantPort)
				}
			}

			// Test BackendTunnel.EndpointHostPort
			tun := &BackendTunnel{Endpoint: tc.input}
			tHost, tPort, tErr := tun.EndpointHostPort()
			if (tErr != nil) != tc.wantErr {
				t.Fatalf("EndpointHostPort err = %v, wantErr = %v", tErr, tc.wantErr)
			}
			if !tc.wantErr {
				if tHost != tc.wantHost {
					t.Errorf("tHost = %q, want %q", tHost, tc.wantHost)
				}
				if tPort != tc.wantPort {
					t.Errorf("tPort = %q, want %q", tPort, tc.wantPort)
				}
			}
		})
	}

	formatCases := []struct {
		name        string
		host        string
		defaultPort int
		want        string
	}{
		{
			name:        "unbracketed ipv6 adds brackets",
			host:        "2001:db8::10",
			defaultPort: 443,
			want:        "[2001:db8::10]:443",
		},
		{
			name:        "bracketed ipv6 retains single brackets",
			host:        "[2001:db8::10]",
			defaultPort: 443,
			want:        "[2001:db8::10]:443",
		},
		{
			name:        "bracketed ipv6 with port preserves existing port",
			host:        "[2001:db8::10]:8443",
			defaultPort: 443,
			want:        "[2001:db8::10]:8443",
		},
		{
			name:        "ipv4 standard",
			host:        "192.0.2.1",
			defaultPort: 443,
			want:        "192.0.2.1:443",
		},
		{
			name:        "ipv4 with port",
			host:        "192.0.2.1:8443",
			defaultPort: 443,
			want:        "192.0.2.1:8443",
		},
		{
			name:        "hostname",
			host:        "backend.example.com",
			defaultPort: 443,
			want:        "backend.example.com:443",
		},
		{
			name:        "hostname with port",
			host:        "backend.example.com:8443",
			defaultPort: 443,
			want:        "backend.example.com:8443",
		},
	}

	for _, tc := range formatCases {
		t.Run("FormatEndpoint/"+tc.name, func(t *testing.T) {
			got := FormatEndpoint(tc.host, tc.defaultPort)
			if got != tc.want {
				t.Errorf("FormatEndpoint(%q, %d) = %q, want %q", tc.host, tc.defaultPort, got, tc.want)
			}
		})
	}
}

func TestBackendTunnel_EndpointHostPort_Nil(t *testing.T) {
	var tun *BackendTunnel
	_, _, err := tun.EndpointHostPort()
	if err == nil {
		t.Fatal("expected error on nil tunnel, got nil")
	}
}
