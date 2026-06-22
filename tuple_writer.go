package sdk

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	"atol.sh/sdk-go/zanzibar"
)

// tupleWriter abstracts tuple persistence so tests can write locally
// while production writes through to the control plane.
type tupleWriter interface {
	grant(ctx context.Context, user, relation, object string) error
	revoke(ctx context.Context, user, relation, object string) error
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
