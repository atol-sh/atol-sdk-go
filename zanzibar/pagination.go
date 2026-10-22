package zanzibar

import (
	"context"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// ReadTuplePage reads one bounded keyset page. It intentionally has no
// unbounded Read fallback because callers use it for bounded durable scans.
func (e *Engine) ReadTuplePage(
	ctx context.Context,
	filter model.TupleFilter,
	cursor string,
	limit int,
) ([]model.Tuple, string, error) {
	pager, ok := e.store.(store.TuplePageStore)
	if !ok {
		return nil, "", store.ErrTuplePageUnsupported
	}
	return pager.ReadPage(ctx, filter, cursor, limit)
}

// TupleCursorAfter creates a store-scoped continuation cursor for an already
// returned tuple. It is used when a caller stops before consuming a full page.
func (e *Engine) TupleCursorAfter(
	ctx context.Context,
	filter model.TupleFilter,
	tuple model.Tuple,
) (string, error) {
	pager, ok := e.store.(store.TuplePageStore)
	if !ok {
		return "", store.ErrTuplePageUnsupported
	}
	return pager.CursorAfter(ctx, filter, tuple)
}

// ReadTuplePageExcludingSubject performs a bounded scan while omitting one
// exact subject. It has no unbounded fallback.
func (e *Engine) ReadTuplePageExcludingSubject(
	ctx context.Context,
	filter model.TupleFilter,
	excludedUserType, excludedUserID, cursor string,
	limit int,
) ([]model.Tuple, string, error) {
	pager, ok := e.store.(store.TupleSubjectExcludingPageStore)
	if !ok {
		return nil, "", store.ErrTuplePageUnsupported
	}
	return pager.ReadPageExcludingSubject(ctx, filter, excludedUserType, excludedUserID, cursor, limit)
}

// TupleCursorAfterExcludingSubject creates a continuation cursor bound to the
// exact exclusion predicate.
func (e *Engine) TupleCursorAfterExcludingSubject(
	ctx context.Context,
	filter model.TupleFilter,
	excludedUserType, excludedUserID string,
	tuple model.Tuple,
) (string, error) {
	pager, ok := e.store.(store.TupleSubjectExcludingPageStore)
	if !ok {
		return "", store.ErrTuplePageUnsupported
	}
	return pager.CursorAfterExcludingSubject(ctx, filter, excludedUserType, excludedUserID, tuple)
}
