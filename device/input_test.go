package device

import (
	"testing"
)

func TestInjectOPAInput_NilDevice(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"user":   "user:123",
		"action": "read",
	}

	result := InjectOPAInput(input, nil)

	if _, ok := result["device"]; ok {
		t.Error("expected no 'device' key for nil DeviceContext")
	}
	if result["user"] != "user:123" {
		t.Error("existing keys should be preserved")
	}
}

func TestInjectOPAInput_DeviceWithoutSignals(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"user":   "user:456",
		"action": "write",
	}

	dc := &DeviceContext{
		DeviceID:   "dev_abc",
		Known:      true,
		Confidence: 0.87,
	}

	result := InjectOPAInput(input, dc)

	d, ok := result["device"].(map[string]any)
	if !ok {
		t.Fatal("expected 'device' key to be a map")
	}

	if d["id"] != "dev_abc" {
		t.Errorf("device.id = %v, want %q", d["id"], "dev_abc")
	}
	if d["known"] != true {
		t.Errorf("device.known = %v, want true", d["known"])
	}
	if d["confidence"] != 0.87 {
		t.Errorf("device.confidence = %v, want 0.87", d["confidence"])
	}
	if _, ok := d["signals"]; ok {
		t.Error("expected no 'signals' key when Signals is nil")
	}

	// Existing keys should be preserved.
	if result["user"] != "user:456" {
		t.Error("existing 'user' key was modified")
	}
}

func TestInjectOPAInput_DeviceWithSignals(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"user": "user:789",
	}

	dc := &DeviceContext{
		DeviceID:   "dev_xyz",
		Known:      false,
		Confidence: 0.42,
		Signals: &SmartSignals{
			Bot:          true,
			VPN:          false,
			Proxy:        true,
			Tor:          false,
			Incognito:    true,
			Tampered:     false,
			Emulator:     true,
			Rooted:       false,
			GeoMismatch:  true,
			AnomalyScore: 0.91,
		},
	}

	result := InjectOPAInput(input, dc)

	d, ok := result["device"].(map[string]any)
	if !ok {
		t.Fatal("expected 'device' key to be a map")
	}

	signals, ok := d["signals"].(map[string]any)
	if !ok {
		t.Fatal("expected 'signals' key to be a map")
	}

	tests := []struct {
		key  string
		want any
	}{
		{"bot", true},
		{"vpn", false},
		{"proxy", true},
		{"tor", false},
		{"incognito", true},
		{"tampered", false},
		{"emulator", true},
		{"rooted", false},
		{"geo_mismatch", true},
		{"anomaly_score", 0.91},
	}

	for _, tt := range tests {
		got, ok := signals[tt.key]
		if !ok {
			t.Errorf("signals[%q] missing", tt.key)
			continue
		}
		if got != tt.want {
			t.Errorf("signals[%q] = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestInjectOPAInput_PreservesExistingKeys(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"user":         "user:100",
		"action":       "delete",
		"org":          "org_abc",
		"client_ip":    "192.168.1.1",
		"mfa_verified": true,
	}

	dc := &DeviceContext{
		DeviceID:   "dev_preserve",
		Known:      true,
		Confidence: 1.0,
	}

	result := InjectOPAInput(input, dc)

	// All original keys should still be present.
	if result["user"] != "user:100" {
		t.Error("user key was modified")
	}
	if result["action"] != "delete" {
		t.Error("action key was modified")
	}
	if result["org"] != "org_abc" {
		t.Error("org key was modified")
	}
	if result["client_ip"] != "192.168.1.1" {
		t.Error("client_ip key was modified")
	}
	if result["mfa_verified"] != true {
		t.Error("mfa_verified key was modified")
	}

	// Device key should be added.
	if _, ok := result["device"]; !ok {
		t.Error("device key should be present")
	}
}
