package models

import (
	"encoding/json"
	"testing"
)

func TestMultiProtocol_ValidProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		valid    bool
	}{
		{"awg canonical", ProtocolAWG, true},
		{"vless canonical", ProtocolVLESS, true},
		{"naive canonical", ProtocolNaive, true},
		{"telemt canonical", "telemt", true},
		{"dns canonical", "dns", true},
		{"awg alias awg2", "awg2", true},
		{"awg alias awg_legacy", "awg_legacy", true},
		{"vless alias hyphen", "vless-reality", true},
		{"vless alias underscore", "vless_reality", true},
		{"naive alias", "naiveproxy", true},
		{"unknown protocol", "unknown", false},
		{"empty protocol", "", false},
		{"unsupported wireguard", "wireguard", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidProtocol(tt.protocol)
			if got != tt.valid {
				t.Errorf("IsValidProtocol(%q) = %v, want %v", tt.protocol, got, tt.valid)
			}
		})
	}
}

func TestMultiProtocol_ContainerNameAndConfigPath(t *testing.T) {
	tests := []struct {
		proto         string
		wantContainer string
		wantConfig    string
		wantOK        bool
	}{
		{ProtocolAWG, "amnezia-awg", "/opt/amnezia/awg/awg0.conf", true},
		{ProtocolVLESS, "amnezia-xray", "/opt/amnezia/xray/config.json", true},
		{"vless-reality", "amnezia-xray", "/opt/amnezia/xray/config.json", true},
		{ProtocolNaive, "amnezia-caddy", "/opt/amnezia/caddy/Caddyfile", true},
		{"naiveproxy", "amnezia-caddy", "/opt/amnezia/caddy/Caddyfile", true},
		{"telemt", "telemt", "/opt/mtproxyl/settings.conf", true},
		{"dns", "amnezia-dns", "/opt/amnezia/dns/unbound.conf", true},
		{"invalid", "", "", false},
		{"", "", "", false},
	}

	for _, tt := range tests {
		t.Run("protocol_"+tt.proto, func(t *testing.T) {
			container, ok := ContainerNameForProtocol(tt.proto)
			if ok != tt.wantOK || container != tt.wantContainer {
				t.Errorf("ContainerNameForProtocol(%q) = (%q, %v), want (%q, %v)",
					tt.proto, container, ok, tt.wantContainer, tt.wantOK)
			}
			config, ok := ConfigPathForProtocol(tt.proto)
			if ok != tt.wantOK || config != tt.wantConfig {
				t.Errorf("ConfigPathForProtocol(%q) = (%q, %v), want (%q, %v)",
					tt.proto, config, ok, tt.wantConfig, tt.wantOK)
			}
		})
	}
}

func TestMultiProtocol_SameTunnelIdentity(t *testing.T) {
	t.Run("awg empty protocol matches awg explicit", func(t *testing.T) {
		t1 := &BackendTunnel{
			ID:              1,
			Endpoint:        "10.0.0.1:51820",
			Protocol:        "",
			PublicKey:       "pub1",
			PrivateKey:      "priv1",
			ProbePrivateKey: "probe1",
		}
		t2 := &BackendTunnel{
			ID:              1,
			Endpoint:        "10.0.0.1:51820",
			Protocol:        ProtocolAWG,
			PublicKey:       "pub1",
			PrivateKey:      "priv1",
			ProbePrivateKey: "probe1",
		}
		if !SameTunnelIdentity(t1, t2) {
			t.Error("expected AWG tunnel with empty protocol to match ProtocolAWG")
		}
	})

	t.Run("vless identical parameters match", func(t *testing.T) {
		params := []byte(`{"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision","public_key":"pk1","short_id":"abcd","server_name":"cam.example.com","fingerprint":"chrome","transport":"tcp"}`)
		t1 := &BackendTunnel{
			ID:             10,
			Endpoint:       "203.0.113.1:443",
			Protocol:       ProtocolVLESS,
			ProtocolParams: params,
		}
		t2 := &BackendTunnel{
			ID:             10,
			Endpoint:       "203.0.113.1:443",
			Protocol:       ProtocolVLESS,
			ProtocolParams: params,
		}
		if !SameTunnelIdentity(t1, t2) {
			t.Error("expected identical VLESS tunnels to match")
		}
	})

	t.Run("vless canonical json equality with key reordering and whitespace", func(t *testing.T) {
		p1 := []byte(`{"uuid":"u1","server_name":"example.com","public_key":"pk"}`)
		p2 := []byte(`{  "public_key": "pk",  "uuid": "u1",  "server_name": "example.com"  }`)
		t1 := &BackendTunnel{ID: 10, Endpoint: "203.0.113.1:443", Protocol: ProtocolVLESS, ProtocolParams: p1}
		t2 := &BackendTunnel{ID: 10, Endpoint: "203.0.113.1:443", Protocol: ProtocolVLESS, ProtocolParams: p2}
		if !SameTunnelIdentity(t1, t2) {
			t.Error("expected reordered/whitespace VLESS JSON to match via canonical comparison")
		}
	})

	t.Run("vless parameter difference breaks identity", func(t *testing.T) {
		p1 := []byte(`{"uuid":"u1","server_name":"example.com"}`)
		p2 := []byte(`{"uuid":"u2","server_name":"example.com"}`)
		t1 := &BackendTunnel{ID: 10, Endpoint: "203.0.113.1:443", Protocol: ProtocolVLESS, ProtocolParams: p1}
		t2 := &BackendTunnel{ID: 10, Endpoint: "203.0.113.1:443", Protocol: ProtocolVLESS, ProtocolParams: p2}
		if SameTunnelIdentity(t1, t2) {
			t.Error("expected different VLESS parameters to not match")
		}
	})

	t.Run("naiveproxy identical parameters match", func(t *testing.T) {
		p1 := []byte(`{"username":"user1","password":"secret","domain":"proxy.example.com","enable_h3":true}`)
		p2 := []byte(`{"enable_h3":true,"password":"secret","username":"user1","domain":"proxy.example.com"}`)
		t1 := &BackendTunnel{ID: 20, Endpoint: "203.0.113.2:443", Protocol: ProtocolNaive, ProtocolParams: p1}
		t2 := &BackendTunnel{ID: 20, Endpoint: "203.0.113.2:443", Protocol: ProtocolNaive, ProtocolParams: p2}
		if !SameTunnelIdentity(t1, t2) {
			t.Error("expected identical NaiveProxy tunnels to match")
		}
	})

	t.Run("naiveproxy parameter difference breaks identity", func(t *testing.T) {
		p1 := []byte(`{"username":"user1","password":"secret","domain":"proxy.example.com","enable_h3":true}`)
		p2 := []byte(`{"username":"user1","password":"secret","domain":"proxy.example.com","enable_h3":false}`)
		t1 := &BackendTunnel{ID: 20, Endpoint: "203.0.113.2:443", Protocol: ProtocolNaive, ProtocolParams: p1}
		t2 := &BackendTunnel{ID: 20, Endpoint: "203.0.113.2:443", Protocol: ProtocolNaive, ProtocolParams: p2}
		if SameTunnelIdentity(t1, t2) {
			t.Error("expected different NaiveProxy enable_h3 to not match")
		}
	})

	t.Run("protocol mismatch fails identity", func(t *testing.T) {
		t1 := &BackendTunnel{ID: 1, Endpoint: "10.0.0.1:443", Protocol: ProtocolAWG}
		t2 := &BackendTunnel{ID: 1, Endpoint: "10.0.0.1:443", Protocol: ProtocolVLESS}
		t3 := &BackendTunnel{ID: 1, Endpoint: "10.0.0.1:443", Protocol: ProtocolNaive}
		if SameTunnelIdentity(t1, t2) {
			t.Error("expected AWG vs VLESS to not match")
		}
		if SameTunnelIdentity(t2, t3) {
			t.Error("expected VLESS vs Naive to not match")
		}
	})

	t.Run("endpoint or id mismatch fails", func(t *testing.T) {
		params := []byte(`{"uuid":"u1"}`)
		t1 := &BackendTunnel{ID: 1, Endpoint: "10.0.0.1:443", Protocol: ProtocolVLESS, ProtocolParams: params}
		t2 := &BackendTunnel{ID: 2, Endpoint: "10.0.0.1:443", Protocol: ProtocolVLESS, ProtocolParams: params}
		t3 := &BackendTunnel{ID: 1, Endpoint: "10.0.0.2:443", Protocol: ProtocolVLESS, ProtocolParams: params}
		if SameTunnelIdentity(t1, t2) {
			t.Error("expected ID difference to break identity")
		}
		if SameTunnelIdentity(t1, t3) {
			t.Error("expected Endpoint difference to break identity")
		}
	})
}

func TestMultiProtocol_InstallProtocolRequestValidation(t *testing.T) {
	t.Run("valid vless options", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolVLESS,
			Port:     "443",
			VLESSOptions: &VLESSInstallOptions{
				Port:       "8443",
				ServerName: "cam.example.com",
				Flow:       "xtls-rprx-vision",
			},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("invalid vless port", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolVLESS,
			Port:     "443",
			VLESSOptions: &VLESSInstallOptions{
				Port: "99999",
			},
		}
		if err := req.Validate(); err == nil {
			t.Error("expected error for out-of-range vless port")
		}
	})

	t.Run("invalid vless server_name", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolVLESS,
			Port:     "443",
			VLESSOptions: &VLESSInstallOptions{
				ServerName: "bad domain with spaces!",
			},
		}
		if err := req.Validate(); err == nil {
			t.Error("expected error for invalid vless server_name")
		}
	})

	t.Run("valid naive options", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolNaive,
			Port:     "443",
			NaiveOptions: &NaiveInstallOptions{
				Port:          "443",
				Domain:        "naive.example.com",
				DecoyTemplate: "filebrowser",
			},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("invalid naive port", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolNaive,
			Port:     "443",
			NaiveOptions: &NaiveInstallOptions{
				Port: "0",
			},
		}
		if err := req.Validate(); err == nil {
			t.Error("expected error for port 0")
		}
	})

	t.Run("invalid naive domain", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: ProtocolNaive,
			Port:     "443",
			NaiveOptions: &NaiveInstallOptions{
				Domain: "bad domain with $pecial!",
			},
		}
		if err := req.Validate(); err == nil {
			t.Error("expected error for invalid naive domain")
		}
	})

	t.Run("valid protocol with normalized alias", func(t *testing.T) {
		req := InstallProtocolRequest{
			Protocol: "vless-reality",
			Port:     "443",
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if req.Protocol != ProtocolVLESS {
			t.Errorf("expected normalized protocol %q, got %q", ProtocolVLESS, req.Protocol)
		}
	})
}

func TestMultiProtocol_ParamStructsSerialization(t *testing.T) {
	vless := VLESSRealityParams{
		UUID:        "uuid-1234",
		Flow:        "xtls-rprx-vision",
		PublicKey:   "pubkey-vless",
		ShortID:     "sid",
		ServerName:  "reality.example.com",
		Fingerprint: "chrome",
		Transport:   "tcp",
	}
	data, err := json.Marshal(vless)
	if err != nil {
		t.Fatalf("marshal VLESSRealityParams failed: %v", err)
	}
	var unmarshaledVLESS VLESSRealityParams
	if err := json.Unmarshal(data, &unmarshaledVLESS); err != nil {
		t.Fatalf("unmarshal VLESSRealityParams failed: %v", err)
	}
	if unmarshaledVLESS != vless {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", unmarshaledVLESS, vless)
	}

	naive := NaiveProxyParams{
		Username: "admin",
		Password: "supersecretpassword",
		Domain:   "proxy.example.com",
		EnableH3: true,
	}
	naiveData, err := json.Marshal(naive)
	if err != nil {
		t.Fatalf("marshal NaiveProxyParams failed: %v", err)
	}
	var unmarshaledNaive NaiveProxyParams
	if err := json.Unmarshal(naiveData, &unmarshaledNaive); err != nil {
		t.Fatalf("unmarshal NaiveProxyParams failed: %v", err)
	}
	if unmarshaledNaive != naive {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", unmarshaledNaive, naive)
	}
}
