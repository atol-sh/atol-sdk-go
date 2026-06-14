// Package encryption provides zero-knowledge encryption key derivation
// and DEK unwrapping for Go applications using Atol authentication.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters -- must match the server (atol control plane).
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

// DeriveKEK derives a Key Encryption Key from the user's password.
// Must use identical parameters as the server (atol control plane).
// The salt is derived deterministically from userID and clientID via HKDF-SHA256.
func DeriveKEK(password, userID, clientID string) ([]byte, error) {
	info := []byte("atol-enc-v1")
	ikm := []byte(userID + "|" + clientID)

	hkdfReader := hkdf.New(sha256.New, ikm, nil, info)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(hkdfReader, salt); err != nil {
		return nil, fmt.Errorf("derive salt: %w", err)
	}

	kek := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return kek, nil
}

// UnwrapDEK decrypts a wrapped DEK using the provided KEK.
// The wrappedDEKBase64 format is base64(nonce12bytes || ciphertext).
func UnwrapDEK(wrappedDEKBase64 string, kek []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(wrappedDEKBase64)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped DEK: %w", err)
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("wrapped DEK too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}

	return dek, nil
}

// WrapDEK encrypts a DEK with the provided KEK using AES-256-GCM.
// Returns base64(nonce || ciphertext).
func WrapDEK(dek, kek []byte) (string, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, dek, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
