package hmac

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestStreamHMACRoundTrip(t *testing.T) {
	original := append(connectTestEnvelope(0, []byte("one")), connectTestEnvelope(1, []byte("two"))...)
	encoded := encodeTestStream(t, original, []byte("stream-key"))
	decoded, err := io.ReadAll(NewVerifiedStreamBody(io.NopCloser(bytes.NewReader(encoded)), []byte("stream-key")))
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %x, want %x", decoded, original)
	}
}

func TestStreamHMACRejectsTamperReorderDeletionDuplicationAndTruncation(t *testing.T) {
	key := []byte("stream-key")
	original := append(connectTestEnvelope(0, []byte("one")), connectTestEnvelope(0, []byte("two"))...)
	encoded := encodeTestStream(t, original, key)
	frames := splitOuterFrames(t, encoded)
	if len(frames) != 3 {
		t.Fatalf("encoded frames = %d, want two data plus close", len(frames))
	}

	tampered := append([]byte(nil), encoded...)
	tampered[5+18+streamMACSize] ^= 0x01
	tests := []struct {
		name string
		body []byte
		want error
	}{
		{"tamper", tampered, ErrStreamIntegrity},
		{"reorder", concatFrames(frames[1], frames[0], frames[2]), ErrStreamSequence},
		{"delete", concatFrames(frames[0], frames[2]), ErrStreamSequence},
		{"duplicate", concatFrames(frames[0], frames[0], frames[1], frames[2]), ErrStreamSequence},
		{"missing close", concatFrames(frames[0], frames[1]), ErrStreamTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := io.ReadAll(NewVerifiedStreamBody(io.NopCloser(bytes.NewReader(test.body)), key))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStreamHMACRejectsWrongKey(t *testing.T) {
	encoded := encodeTestStream(t, connectTestEnvelope(0, []byte("one")), []byte("correct"))
	_, err := io.ReadAll(NewVerifiedStreamBody(io.NopCloser(bytes.NewReader(encoded)), []byte("wrong")))
	if !errors.Is(err, ErrStreamIntegrity) {
		t.Fatalf("error = %v, want ErrStreamIntegrity", err)
	}
}

func encodeTestStream(t *testing.T, original, key []byte) []byte {
	t.Helper()
	body := NewStreamBody(context.Background(), io.NopCloser(bytes.NewReader(original)), key)
	encoded, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("encode stream: %v", err)
	}
	return encoded
}

func connectTestEnvelope(flags byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = flags
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func splitOuterFrames(t *testing.T, encoded []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for len(encoded) > 0 {
		if len(encoded) < 5 {
			t.Fatalf("short outer header")
		}
		length := int(binary.BigEndian.Uint32(encoded[1:5]))
		if len(encoded) < 5+length {
			t.Fatalf("short outer frame")
		}
		frames = append(frames, append([]byte(nil), encoded[:5+length]...))
		encoded = encoded[5+length:]
	}
	return frames
}

func concatFrames(frames ...[]byte) []byte {
	return bytes.Join(frames, nil)
}

func FuzzVerifiedStreamBody(f *testing.F) {
	key := []byte("fuzz-stream-key")
	valid, err := io.ReadAll(NewStreamBody(
		context.Background(),
		io.NopCloser(bytes.NewReader(connectTestEnvelope(0, []byte("seed")))),
		key,
	))
	if err != nil {
		f.Fatalf("encode seed stream: %v", err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 1, 0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2*MaxStreamPayloadSize {
			body = body[:2*MaxStreamPayloadSize]
		}
		_, _ = io.ReadAll(NewVerifiedStreamBody(io.NopCloser(bytes.NewReader(body)), key))
	})
}
