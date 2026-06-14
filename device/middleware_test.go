package device

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMiddleware_Disabled(t *testing.T) {
	t.Parallel()

	cfg := Config{Enabled: false}
	handler := HTTPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dc := DeviceFromContext(r.Context())
		if dc != nil {
			t.Error("expected nil DeviceContext when disabled")
		}
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	r.Header.Set(headerDeviceID, "dev_should_be_ignored")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHTTPMiddleware_NoHeader(t *testing.T) {
	t.Parallel()

	cfg := Config{Enabled: true}
	handler := HTTPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dc := DeviceFromContext(r.Context())
		if dc != nil {
			t.Error("expected nil DeviceContext when no header present")
		}
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHTTPMiddleware_WithDeviceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		deviceID string
	}{
		{
			name:     "standard device ID",
			deviceID: "dev_01HYX5KBQR2T3N4VWZMAPQBG7E",
		},
		{
			name:     "ULID device ID",
			deviceID: "01HYX5KBQR2T3N4VWZMAPQBG7E",
		},
		{
			name:     "short ID",
			deviceID: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := Config{Enabled: true}
			var capturedDC *DeviceContext

			handler := HTTPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedDC = DeviceFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			r.Header.Set(headerDeviceID, tt.deviceID)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			if capturedDC == nil {
				t.Fatal("expected non-nil DeviceContext")
			}
			if capturedDC.DeviceID != tt.deviceID {
				t.Errorf("DeviceID = %q, want %q", capturedDC.DeviceID, tt.deviceID)
			}
			if capturedDC.Known {
				t.Error("Known should be false (default)")
			}
			if capturedDC.Confidence != 0.0 {
				t.Errorf("Confidence = %f, want 0.0 (default)", capturedDC.Confidence)
			}
		})
	}
}

func TestHTTPMiddleware_EmptyHeader(t *testing.T) {
	t.Parallel()

	cfg := Config{Enabled: true}
	handler := HTTPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dc := DeviceFromContext(r.Context())
		if dc != nil {
			t.Error("expected nil DeviceContext for empty header value")
		}
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	r.Header.Set(headerDeviceID, "")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
