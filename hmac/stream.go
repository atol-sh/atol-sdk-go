package hmac

import (
	"bytes"
	"context"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// StreamProtocol identifies the breaking streaming-HMAC wire protocol.
	StreamProtocol = "stream-hmac-v1"
	// StreamNonceBytes is the required random nonce size for each stream.
	StreamNonceBytes = 32
	// MaxStreamPayloadSize bounds one original Connect request message.
	MaxStreamPayloadSize = 5 << 20

	streamFrameData  = byte(0)
	streamFrameClose = byte(1)
	streamMACSize    = sha256.Size
	streamFixedSize  = 4 + 1 + 1 + 8 + streamMACSize + 4 + streamMACSize
)

var (
	streamMagic        = [4]byte{'A', 'T', 'H', '1'}
	ErrStreamMalformed = errors.New("stream-hmac: malformed frame")
	ErrStreamIntegrity = errors.New("stream-hmac: integrity check failed")
	ErrStreamSequence  = errors.New("stream-hmac: invalid sequence")
	ErrStreamTruncated = errors.New("stream-hmac: authenticated close frame missing")
)

// IsStreamingContentType identifies Connect and gRPC streaming media types.
// Connect unary requests use application/proto or application/json; Connect
// streaming requests use application/connect+proto or +json.
func IsStreamingContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return strings.HasPrefix(mediaType, "application/connect+") ||
		strings.HasPrefix(mediaType, "application/grpc")
}

// ComputeStreamInit computes the domain-separated stream-init signature.
func ComputeStreamInit(secret, timestamp, method, path, nonce string) string {
	canonical := "ATOL-HMAC-SHA256\n" + StreamProtocol + "\n" + timestamp + "\n" + method + "\n" + path + "\n" + nonce
	mac := stdhmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// DeriveStreamKey derives the per-stream frame key from the API secret and
// authenticated request metadata. nonce must be a raw URL-base64 32-byte value.
func DeriveStreamKey(secret, timestamp, method, path, nonce string) ([]byte, error) {
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(nonceBytes) != StreamNonceBytes {
		return nil, fmt.Errorf("derive stream key: invalid nonce")
	}
	mac := stdhmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("atol-stream-key/v1\x00"))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(path))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(nonceBytes)
	return mac.Sum(nil), nil
}

// NewStreamBody wraps Connect request envelopes with per-frame HMAC metadata
// and appends an authenticated close frame when body reaches EOF.
func NewStreamBody(ctx context.Context, body io.ReadCloser, key []byte) io.ReadCloser {
	reader, writer := io.Pipe()
	go func() {
		defer body.Close()
		err := encodeStream(ctx, body, writer, key)
		_ = writer.CloseWithError(err)
	}()
	return reader
}

// NewVerifiedStreamBody verifies and strips stream-hmac-v1 frames, exposing
// the original Connect envelopes to the server parser. EOF is returned only
// after a valid authenticated close frame.
func NewVerifiedStreamBody(body io.ReadCloser, key []byte) io.ReadCloser {
	return &verifiedStreamReader{source: body, key: append([]byte(nil), key...)}
}

func encodeStream(ctx context.Context, source io.Reader, target io.Writer, key []byte) error {
	var sequence uint64
	previous := make([]byte, streamMACSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var header [5]byte
		_, err := io.ReadFull(source, header[:])
		if errors.Is(err, io.EOF) {
			frame, mac := marshalStreamFrame(key, streamFrameClose, 0, sequence, previous, nil)
			if err := writeOuterFrame(target, frame); err != nil {
				return err
			}
			copy(previous, mac)
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: request envelope header", ErrStreamMalformed)
		}
		payloadLength := binary.BigEndian.Uint32(header[1:])
		if payloadLength > MaxStreamPayloadSize {
			return fmt.Errorf("%w: payload exceeds %d bytes", ErrStreamMalformed, MaxStreamPayloadSize)
		}
		payload := make([]byte, payloadLength)
		if _, err := io.ReadFull(source, payload); err != nil {
			return fmt.Errorf("%w: request envelope payload", ErrStreamMalformed)
		}
		frame, mac := marshalStreamFrame(key, streamFrameData, header[0], sequence, previous, payload)
		if err := writeOuterFrame(target, frame); err != nil {
			return err
		}
		copy(previous, mac)
		sequence++
	}
}

func writeOuterFrame(target io.Writer, frame []byte) error {
	var header [5]byte
	binary.BigEndian.PutUint32(header[1:], uint32(len(frame)))
	if _, err := target.Write(header[:]); err != nil {
		return err
	}
	if _, err := target.Write(frame); err != nil {
		return err
	}
	return nil
}

func marshalStreamFrame(key []byte, kind, originalFlags byte, sequence uint64, previous, payload []byte) ([]byte, []byte) {
	frame := make([]byte, streamFixedSize+len(payload))
	copy(frame[:4], streamMagic[:])
	frame[4] = kind
	frame[5] = originalFlags
	binary.BigEndian.PutUint64(frame[6:14], sequence)
	copy(frame[14:14+streamMACSize], previous)
	binary.BigEndian.PutUint32(frame[14+streamMACSize:18+streamMACSize], uint32(len(payload)))
	copy(frame[18+streamMACSize:18+streamMACSize+len(payload)], payload)
	macOffset := len(frame) - streamMACSize
	mac := frameMAC(key, frame[:macOffset])
	copy(frame[macOffset:], mac)
	return frame, mac
}

func frameMAC(key, authenticatedFrame []byte) []byte {
	mac := stdhmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("atol-stream-frame/v1\x00"))
	_, _ = mac.Write(authenticatedFrame)
	return mac.Sum(nil)
}

type verifiedStreamReader struct {
	source   io.ReadCloser
	key      []byte
	sequence uint64
	previous [streamMACSize]byte
	pending  []byte
	closed   bool
}

func (r *verifiedStreamReader) Read(target []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.closed {
			return 0, io.EOF
		}
		if err := r.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(target, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *verifiedStreamReader) Close() error { return r.source.Close() }

func (r *verifiedStreamReader) readFrame() error {
	var outer [5]byte
	_, err := io.ReadFull(r.source, outer[:])
	if errors.Is(err, io.EOF) {
		return ErrStreamTruncated
	}
	if err != nil || outer[0] != 0 {
		return ErrStreamMalformed
	}
	frameLength := binary.BigEndian.Uint32(outer[1:])
	if frameLength < streamFixedSize || frameLength > streamFixedSize+MaxStreamPayloadSize {
		return ErrStreamMalformed
	}
	frame := make([]byte, frameLength)
	if _, err := io.ReadFull(r.source, frame); err != nil {
		return ErrStreamMalformed
	}
	if !bytes.Equal(frame[:4], streamMagic[:]) {
		return ErrStreamMalformed
	}
	kind, originalFlags := frame[4], frame[5]
	sequence := binary.BigEndian.Uint64(frame[6:14])
	if sequence != r.sequence || !stdhmac.Equal(frame[14:14+streamMACSize], r.previous[:]) {
		return ErrStreamSequence
	}
	payloadLength := binary.BigEndian.Uint32(frame[14+streamMACSize : 18+streamMACSize])
	if int(payloadLength) != len(frame)-streamFixedSize {
		return ErrStreamMalformed
	}
	macOffset := len(frame) - streamMACSize
	wantMAC := frameMAC(r.key, frame[:macOffset])
	if !stdhmac.Equal(frame[macOffset:], wantMAC) {
		return ErrStreamIntegrity
	}
	copy(r.previous[:], wantMAC)
	r.sequence++
	payload := frame[18+streamMACSize : macOffset]

	switch kind {
	case streamFrameData:
		var header [5]byte
		header[0] = originalFlags
		binary.BigEndian.PutUint32(header[1:], payloadLength)
		r.pending = make([]byte, 0, len(header)+len(payload))
		r.pending = append(r.pending, header[:]...)
		r.pending = append(r.pending, payload...)
		return nil
	case streamFrameClose:
		if originalFlags != 0 || payloadLength != 0 {
			return ErrStreamMalformed
		}
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			return ErrStreamMalformed
		}
		r.closed = true
		return nil
	default:
		return ErrStreamMalformed
	}
}
