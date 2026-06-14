package device

import (
	"context"
	"testing"
)

func TestContextWithDevice_RoundTrip(t *testing.T) {
	t.Parallel()

	dc := &DeviceContext{
		DeviceID:   "dev_abc123",
		Known:      true,
		Confidence: 0.95,
		Signals: &SmartSignals{
			Bot: false,
			VPN: true,
		},
	}

	ctx := ContextWithDevice(context.Background(), dc)
	got := DeviceFromContext(ctx)

	if got == nil {
		t.Fatal("expected non-nil DeviceContext from context")
	}
	if got.DeviceID != "dev_abc123" {
		t.Errorf("DeviceID = %q, want %q", got.DeviceID, "dev_abc123")
	}
	if !got.Known {
		t.Error("Known = false, want true")
	}
	if got.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", got.Confidence)
	}
	if got.Signals == nil {
		t.Fatal("Signals is nil, want non-nil")
	}
	if got.Signals.Bot {
		t.Error("Signals.Bot = true, want false")
	}
	if !got.Signals.VPN {
		t.Error("Signals.VPN = false, want true")
	}
}

func TestDeviceFromContext_Empty(t *testing.T) {
	t.Parallel()

	got := DeviceFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil DeviceContext from empty context, got %+v", got)
	}
}

func TestContextWithDevice_Overwrite(t *testing.T) {
	t.Parallel()

	first := &DeviceContext{DeviceID: "first"}
	second := &DeviceContext{DeviceID: "second"}

	ctx := ContextWithDevice(context.Background(), first)
	ctx = ContextWithDevice(ctx, second)

	got := DeviceFromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil DeviceContext")
	}
	if got.DeviceID != "second" {
		t.Errorf("DeviceID = %q, want %q (last set wins)", got.DeviceID, "second")
	}
}

func TestDeviceContext_NilSignals(t *testing.T) {
	t.Parallel()

	dc := &DeviceContext{
		DeviceID:   "dev_no_signals",
		Known:      false,
		Confidence: 0.0,
		Signals:    nil,
	}

	ctx := ContextWithDevice(context.Background(), dc)
	got := DeviceFromContext(ctx)

	if got == nil {
		t.Fatal("expected non-nil DeviceContext")
	}
	if got.Signals != nil {
		t.Errorf("Signals = %+v, want nil", got.Signals)
	}
}
