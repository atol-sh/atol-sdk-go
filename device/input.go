package device

// InjectOPAInput enriches an OPA input map with device intelligence data.
// It sets input["device"] with the device ID, known status, confidence,
// and smart signals so that Rego policies can reference them as
// input.device.id, input.device.known, input.device.confidence, and
// input.device.signals.*.
//
// If device is nil, the input map is returned unmodified.
func InjectOPAInput(input map[string]any, device *DeviceContext) map[string]any {
	if device == nil {
		return input
	}

	d := map[string]any{
		"id":         device.DeviceID,
		"known":      device.Known,
		"confidence": device.Confidence,
	}

	if device.Signals != nil {
		d["signals"] = map[string]any{
			"bot":           device.Signals.Bot,
			"vpn":           device.Signals.VPN,
			"proxy":         device.Signals.Proxy,
			"tor":           device.Signals.Tor,
			"incognito":     device.Signals.Incognito,
			"tampered":      device.Signals.Tampered,
			"emulator":      device.Signals.Emulator,
			"rooted":        device.Signals.Rooted,
			"geo_mismatch":  device.Signals.GeoMismatch,
			"anomaly_score": device.Signals.AnomalyScore,
		}
	}

	input["device"] = d
	return input
}
