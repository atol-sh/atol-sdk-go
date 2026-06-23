package sdk

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

// lastHolderConnectError builds the FailedPrecondition error the control plane
// returns when a revoke would strand the last required-relation holder,
// including the structured ErrorInfo detail the SDK keys off.
func lastHolderConnectError(t *testing.T) *connect.Error {
	t.Helper()
	cerr := connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot revoke the last holder of a required relation"))
	detail, err := connect.NewErrorDetail(&errdetails.ErrorInfo{
		Reason: lastHolderReason,
		Domain: lastHolderDomain,
	})
	if err != nil {
		t.Fatalf("NewErrorDetail: %v", err)
	}
	cerr.AddDetail(detail)
	return cerr
}

func TestIsLastHolderError(t *testing.T) {
	t.Run("tagged error is detected", func(t *testing.T) {
		if !isLastHolderError(lastHolderConnectError(t)) {
			t.Error("isLastHolderError = false, want true for a LAST_HOLDER-tagged error")
		}
	})

	t.Run("detected through wrapping", func(t *testing.T) {
		wrapped := fmt.Errorf("revoke access: %w", lastHolderConnectError(t))
		if !isLastHolderError(wrapped) {
			t.Error("isLastHolderError = false, want true through a wrapping error")
		}
	})

	t.Run("the returned error matches errors.Is(ErrLastHolder)", func(t *testing.T) {
		// Mirrors what remoteTupleWriter.revoke returns so consumers can rely on
		// errors.Is(err, ErrLastHolder).
		mapped := fmt.Errorf("revoke doc:1#owner@user:a: %w", ErrLastHolder)
		if !errors.Is(mapped, ErrLastHolder) {
			t.Error("errors.Is(mapped, ErrLastHolder) = false, want true")
		}
	})

	t.Run("plain FailedPrecondition without the detail is not last-holder", func(t *testing.T) {
		cerr := connect.NewError(connect.CodeFailedPrecondition, errors.New("some other precondition"))
		if isLastHolderError(cerr) {
			t.Error("isLastHolderError = true, want false without the ErrorInfo detail")
		}
	})

	t.Run("wrong reason is not last-holder", func(t *testing.T) {
		cerr := connect.NewError(connect.CodeFailedPrecondition, errors.New("nope"))
		detail, err := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: "SOMETHING_ELSE", Domain: lastHolderDomain})
		if err != nil {
			t.Fatalf("NewErrorDetail: %v", err)
		}
		cerr.AddDetail(detail)
		if isLastHolderError(cerr) {
			t.Error("isLastHolderError = true, want false for a non-LAST_HOLDER reason")
		}
	})

	t.Run("right reason but wrong domain is not last-holder", func(t *testing.T) {
		// Both Reason and Domain must match: a LAST_HOLDER reason emitted under
		// some other domain is a different contract and must not be mistaken.
		cerr := connect.NewError(connect.CodeFailedPrecondition, errors.New("nope"))
		detail, err := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: lastHolderReason, Domain: "example.com/other"})
		if err != nil {
			t.Fatalf("NewErrorDetail: %v", err)
		}
		cerr.AddDetail(detail)
		if isLastHolderError(cerr) {
			t.Error("isLastHolderError = true, want false for a mismatched domain")
		}
	})

	t.Run("non-connect error is not last-holder", func(t *testing.T) {
		if isLastHolderError(errors.New("plain")) {
			t.Error("isLastHolderError = true, want false for a non-connect error")
		}
		if isLastHolderError(nil) {
			t.Error("isLastHolderError(nil) = true, want false")
		}
	})
}
