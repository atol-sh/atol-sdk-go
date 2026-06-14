package encryption

import (
	"bytes"
	"testing"
)

func TestDeriveKEK_Deterministic(t *testing.T) {
	t.Helper()

	password := "test-password-123"
	userID := "user_abc123"
	clientID := "client_xyz789"

	kek1, err := DeriveKEK(password, userID, clientID)
	if err != nil {
		t.Error("first DeriveKEK failed, want nil error, got", err)
		return
	}
	if len(kek1) != 32 {
		t.Errorf("got KEK length %d, want 32", len(kek1))
	}

	kek2, err := DeriveKEK(password, userID, clientID)
	if err != nil {
		t.Error("second DeriveKEK failed, want nil error, got", err)
		return
	}

	if !bytes.Equal(kek1, kek2) {
		t.Error("got different KEKs for same inputs, want identical")
	}
}

func TestDeriveKEK_PerAppIsolation(t *testing.T) {
	t.Helper()

	password := "same-password"
	userID := "user_abc123"

	kek1, err := DeriveKEK(password, userID, "app-one")
	if err != nil {
		t.Error("DeriveKEK for app-one failed, want nil error, got", err)
		return
	}

	kek2, err := DeriveKEK(password, userID, "app-two")
	if err != nil {
		t.Error("DeriveKEK for app-two failed, want nil error, got", err)
		return
	}

	if bytes.Equal(kek1, kek2) {
		t.Error("got identical KEKs for different client_ids, want different")
	}
}

func TestDeriveKEK_DifferentPassword(t *testing.T) {
	t.Helper()

	userID := "user_abc123"
	clientID := "client_xyz789"

	kek1, err := DeriveKEK("password-one", userID, clientID)
	if err != nil {
		t.Error("DeriveKEK with password-one failed, want nil error, got", err)
		return
	}

	kek2, err := DeriveKEK("password-two", userID, clientID)
	if err != nil {
		t.Error("DeriveKEK with password-two failed, want nil error, got", err)
		return
	}

	if bytes.Equal(kek1, kek2) {
		t.Error("got identical KEKs for different passwords, want different")
	}
}

func TestUnwrapDEK_WithKnownVector(t *testing.T) {
	t.Helper()

	// Generate a known KEK from fixed inputs.
	password := "test-vector-password"
	userID := "user_testvec"
	clientID := "client_testvec"

	kek, err := DeriveKEK(password, userID, clientID)
	if err != nil {
		t.Error("DeriveKEK failed, want nil error, got", err)
		return
	}

	// Create a known DEK and wrap it.
	dek := []byte("this-is-a-32-byte-test-dek-val!")
	if len(dek) != 31 {
		// Pad to 32 bytes.
		dek = append(dek, 0)
	}

	wrapped, err := WrapDEK(dek, kek)
	if err != nil {
		t.Error("WrapDEK failed, want nil error, got", err)
		return
	}

	// Unwrap and verify.
	unwrapped, err := UnwrapDEK(wrapped, kek)
	if err != nil {
		t.Error("UnwrapDEK failed, want nil error, got", err)
		return
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Errorf("got unwrapped DEK %x, want %x", unwrapped, dek)
	}
}

func TestUnwrapDEK_WrongKEK(t *testing.T) {
	t.Helper()

	kek1, err := DeriveKEK("password1", "user1", "client1")
	if err != nil {
		t.Error("DeriveKEK for kek1 failed, want nil error, got", err)
		return
	}

	kek2, err := DeriveKEK("password2", "user2", "client2")
	if err != nil {
		t.Error("DeriveKEK for kek2 failed, want nil error, got", err)
		return
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	wrapped, err := WrapDEK(dek, kek1)
	if err != nil {
		t.Error("WrapDEK failed, want nil error, got", err)
		return
	}

	_, err = UnwrapDEK(wrapped, kek2)
	if err == nil {
		t.Error("got nil error unwrapping with wrong KEK, want error")
	}
}

func TestUnwrapDEK_TooShort(t *testing.T) {
	t.Helper()

	// base64 of a 5-byte value (shorter than 12-byte nonce requirement).
	_, err := UnwrapDEK("AQIDBAU=", make([]byte, 32))
	if err == nil {
		t.Error("got nil error for too-short input, want error")
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	t.Helper()

	kek, err := DeriveKEK("roundtrip-pass", "user_rt", "client_rt")
	if err != nil {
		t.Error("DeriveKEK failed, want nil error, got", err)
		return
	}

	original := make([]byte, 32)
	for i := range original {
		original[i] = byte(i * 7)
	}

	wrapped, err := WrapDEK(original, kek)
	if err != nil {
		t.Error("WrapDEK failed, want nil error, got", err)
		return
	}

	unwrapped, err := UnwrapDEK(wrapped, kek)
	if err != nil {
		t.Error("UnwrapDEK failed, want nil error, got", err)
		return
	}

	if !bytes.Equal(original, unwrapped) {
		t.Errorf("got unwrapped %x, want %x", unwrapped, original)
	}
}
