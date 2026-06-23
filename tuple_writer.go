package sdk

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
)

// tupleWriter abstracts tuple persistence so tests can write locally
// while production writes through to the control plane.
type tupleWriter interface {
	grant(ctx context.Context, user, relation, object string) error
	revoke(ctx context.Context, user, relation, object string) error
}

// ErrLastHolder is returned by RevokeAccess when the revoke would remove the
// last holder of a relation the model marks required, which the control plane
// refuses. Match it with errors.Is(err, ErrLastHolder) rather than inspecting
// the Connect status code: the control plane tags this case with a
// google.rpc.ErrorInfo detail (Reason lastHolderReason, Domain lastHolderDomain)
// and RevokeAccess translates that detail back into this sentinel.
var ErrLastHolder = model.ErrLastHolder

// lastHolderReason and lastHolderDomain are the google.rpc.ErrorInfo fields the
// control plane sets on the FailedPrecondition error it returns when a revoke
// would strand the last required-relation holder. They are a wire contract
// shared with the control-plane access handler; changing either side alone
// breaks ErrLastHolder detection.
const (
	lastHolderReason = "LAST_HOLDER"
	lastHolderDomain = "atol.sh/access"
)

// isLastHolderError reports whether err is the control plane's last-required-
// holder rejection, identified by its structured ErrorInfo detail rather than a
// brittle status-code or message match.
func isLastHolderError(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return false
	}
	for _, d := range cerr.Details() {
		msg, valErr := d.Value()
		if valErr != nil {
			continue
		}
		if info, ok := msg.(*errdetails.ErrorInfo); ok &&
			info.GetReason() == lastHolderReason && info.GetDomain() == lastHolderDomain {
			return true
		}
	}
	return false
}

// remoteTupleWriter writes tuples to the control plane and mirrors locally.
type remoteTupleWriter struct {
	client  apiv1connect.AccessServiceClient
	storeID string
	zEngine *zanzibar.Engine
}

func (w *remoteTupleWriter) grant(ctx context.Context, user, relation, object string) error {
	_, err := w.client.GrantAccess(ctx, connect.NewRequest(&apiv1.GrantAccessRequest{
		OrgId:    w.storeID,
		User:     user,
		Relation: relation,
		Object:   object,
	}))
	if err != nil {
		return fmt.Errorf("grant access: %w", err)
	}
	if err := w.zEngine.WriteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("remote grant succeeded but local mirror failed for %s#%s@%s: %w", object, relation, user, err)
	}
	return nil
}

func (w *remoteTupleWriter) revoke(ctx context.Context, user, relation, object string) error {
	_, err := w.client.RevokeAccess(ctx, connect.NewRequest(&apiv1.RevokeAccessRequest{
		OrgId:    w.storeID,
		User:     user,
		Relation: relation,
		Object:   object,
	}))
	if err != nil {
		if isLastHolderError(err) {
			return fmt.Errorf("revoke %s#%s@%s: %w", object, relation, user, ErrLastHolder)
		}
		return fmt.Errorf("revoke access: %w", err)
	}
	if err := w.zEngine.DeleteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("remote revoke succeeded but local mirror failed for %s#%s@%s: %w", object, relation, user, err)
	}
	return nil
}

// localTupleWriter writes tuples directly to the in-memory store without
// contacting the control plane. Used by the atoltest package.
type localTupleWriter struct {
	zEngine *zanzibar.Engine
}

func (w *localTupleWriter) grant(ctx context.Context, user, relation, object string) error {
	if err := w.zEngine.WriteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("local grant: %w", err)
	}
	return nil
}

func (w *localTupleWriter) revoke(ctx context.Context, user, relation, object string) error {
	if err := w.zEngine.DeleteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("local revoke: %w", err)
	}
	return nil
}
