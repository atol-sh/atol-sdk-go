// Package zanzibar implements a custom Zanzibar-style relationship-based
// access control engine. It provides Check, ListObjects, ListUsers,
// WriteTuple, DeleteTuple, ReadTuples, LoadModel, and GetModel operations.
package zanzibar

import (
	"context"
	"fmt"
	"sync"

	"atol.sh/sdk-go/zanzibar/check"
	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
	zSync "atol.sh/sdk-go/zanzibar/sync"
)

// tenantModel holds a compiled model and its checker for a single tenant.
type tenantModel struct {
	model      *model.Model
	checker    *check.Checker
	sourceYAML []byte // original YAML source for serialization in bootstrap snapshots
}

// modelCache is a thread-safe cache of per-tenant models.
type modelCache struct {
	mu     sync.RWMutex
	models map[string]*tenantModel
}

// Engine is the top-level Zanzibar engine composing model, store, and checker.
type Engine struct {
	mu           sync.RWMutex
	defaultModel *tenantModel
	cache        modelCache
	store        store.TupleStore
	modelStore   store.ModelStore // persistence (nil = no persistence)
	notifier     zSync.ChangeNotifier
}

// New creates a Zanzibar engine with the given store and optional notifier.
// If notifier is nil, a no-op notifier is used.
// If modelStore is nil, per-tenant models are not persisted.
func New(s store.TupleStore, ms store.ModelStore, notifier zSync.ChangeNotifier) *Engine {
	if notifier == nil {
		notifier = zSync.NoopNotifier{}
	}
	return &Engine{
		store:      s,
		modelStore: ms,
		notifier:   notifier,
		cache: modelCache{
			models: make(map[string]*tenantModel),
		},
	}
}

// LoadModel compiles YAML bytes and sets it as the default model (startup path).
func (e *Engine) LoadModel(data []byte) error {
	m, err := model.Compile(data)
	if err != nil {
		return fmt.Errorf("compile model: %w", err)
	}
	e.mu.Lock()
	e.defaultModel = &tenantModel{
		model:      m,
		checker:    check.New(m, e.store),
		sourceYAML: data,
	}
	e.mu.Unlock()
	e.notifier.OnModelUpdate(context.Background(), "", m)
	return nil
}

// SetModel sets a pre-compiled model as the default model.
func (e *Engine) SetModel(m *model.Model) {
	e.mu.Lock()
	e.defaultModel = &tenantModel{
		model:   m,
		checker: check.New(m, e.store),
	}
	e.mu.Unlock()
	e.notifier.OnModelUpdate(context.Background(), "", m)
}

// GetModel returns the default compiled model.
func (e *Engine) GetModel() *model.Model {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.defaultModel == nil {
		return nil
	}
	return e.defaultModel.model
}

// LoadModelForTenant compiles YAML, caches it for the tenant, and persists to DB.
func (e *Engine) LoadModelForTenant(ctx context.Context, tenantID string, data []byte) error {
	m, err := model.Compile(data)
	if err != nil {
		return fmt.Errorf("compile model: %w", err)
	}

	tm := &tenantModel{
		model:      m,
		checker:    check.New(m, e.store),
		sourceYAML: data,
	}

	e.cache.mu.Lock()
	e.cache.models[tenantID] = tm
	e.cache.mu.Unlock()

	// Persist to DB if model store is available.
	if e.modelStore != nil {
		if err := e.modelStore.Save(ctx, tenantID, string(data), "api"); err != nil {
			return fmt.Errorf("persist model: %w", err)
		}
	}

	e.notifier.OnModelUpdate(ctx, tenantID, m)
	return nil
}

// GetModelForTenant returns the tenant-specific model, or the default if none exists.
func (e *Engine) GetModelForTenant(ctx context.Context, tenantID string) *model.Model {
	tm := e.resolveModel(ctx, tenantID)
	if tm == nil {
		return nil
	}
	return tm.model
}

// GetModelSourceYAML returns the original YAML source for the tenant's model.
// Returns nil if no source was stored (e.g., model was set via SetModel).
func (e *Engine) GetModelSourceYAML(ctx context.Context, tenantID string) []byte {
	tm := e.resolveModel(ctx, tenantID)
	if tm == nil {
		return nil
	}
	return tm.sourceYAML
}

// LoadPersistedModels loads all persisted per-tenant models from the DB into cache.
// Called at startup after the default model is loaded.
func (e *Engine) LoadPersistedModels(ctx context.Context) error {
	if e.modelStore == nil {
		return nil
	}

	models, err := e.modelStore.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list persisted models: %w", err)
	}

	for tenantID, yaml := range models {
		m, compileErr := model.Compile([]byte(yaml))
		if compileErr != nil {
			return fmt.Errorf("compile persisted model for tenant %s: %w", tenantID, compileErr)
		}
		tm := &tenantModel{
			model:      m,
			checker:    check.New(m, e.store),
			sourceYAML: []byte(yaml),
		}
		e.cache.mu.Lock()
		e.cache.models[tenantID] = tm
		e.cache.mu.Unlock()
	}

	return nil
}

// resolveModel returns the tenant-specific model, or the default.
func (e *Engine) resolveModel(ctx context.Context, tenantID string) *tenantModel {
	// If tenantID provided directly, use it; otherwise extract from context.
	tid := tenantID
	if tid == "" {
		tid = store.TenantFromContext(ctx)
	}

	if tid != "" {
		e.cache.mu.RLock()
		tm, ok := e.cache.models[tid]
		e.cache.mu.RUnlock()
		if ok {
			return tm
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.defaultModel
}

// Check returns true if the user has the given relation on the object.
// user and object are in "type:id" format.
func (e *Engine) Check(ctx context.Context, user, relation, object string) (bool, error) {
	tm := e.resolveModel(ctx, "")
	if tm == nil || tm.checker == nil {
		return false, fmt.Errorf("no model loaded")
	}

	userType, userID, _ := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	return tm.checker.Check(ctx, userType, userID, relation, objectType, objectID)
}

// CheckWithContextTuples returns true if the user has the given relation on the
// object, considering both stored tuples and the provided ephemeral context tuples.
// Context tuples are never persisted — they exist only for this evaluation.
func (e *Engine) CheckWithContextTuples(ctx context.Context, user, relation, object string, contextTuples []model.Tuple) (bool, error) {
	if len(contextTuples) == 0 {
		return e.Check(ctx, user, relation, object)
	}

	tm := e.resolveModel(ctx, "")
	if tm == nil || tm.checker == nil {
		return false, fmt.Errorf("no model loaded")
	}

	userType, userID, _ := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	return tm.checker.CheckWithContext(ctx, contextTuples, userType, userID, relation, objectType, objectID)
}

// WriteTuple writes a relationship tuple. User is "type:id" or "type:id#relation".
// Object is "type:id". The tuple is validated against the resolved model.
func (e *Engine) WriteTuple(ctx context.Context, user, relation, object string) error {
	userType, userID, userRelation := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	t := model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	}

	// Validate against the resolved model.
	tm := e.resolveModel(ctx, "")
	if tm != nil && tm.model != nil {
		if err := model.ValidateTuple(tm.model, t); err != nil {
			return err
		}
	}

	recorded, err := e.recordTupleWrite(ctx, t)
	if err != nil {
		return err
	}
	if err := e.store.Write(ctx, t); err != nil {
		return err
	}
	if !recorded {
		e.notifier.OnTupleWrite(ctx, t)
	}
	return nil
}

// DeleteTuple removes a relationship tuple. If the tuple's relation declares a
// minimum-holder floor (ADR 0016) and the tuple is direct, the delete is gated
// so it never strands the object below the floor; the delete then runs through
// the store's atomic ConditionalDeleter capability, failing loud if the store
// lacks it. Returns model.ErrLastHolder if the delete would breach the floor.
func (e *Engine) DeleteTuple(ctx context.Context, user, relation, object string) error {
	userType, userID, userRelation := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	t := model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	}

	min := e.minHolders(ctx, objectType, relation)
	if min >= 1 && t.UserRelation == "" {
		deleter, ok := e.store.(store.ConditionalDeleter)
		if !ok {
			return fmt.Errorf("delete %s#%s@%s: relation requires a minimum-holder floor but store does not implement store.ConditionalDeleter", object, relation, user)
		}
		recorded, err := e.recordTupleDelete(ctx, t)
		if err != nil {
			return err
		}
		if err := deleter.DeleteIfAbove(ctx, t, min); err != nil {
			return err
		}
		if !recorded {
			e.notifier.OnTupleDelete(ctx, t)
		}
		return nil
	}

	recorded, err := e.recordTupleDelete(ctx, t)
	if err != nil {
		return err
	}
	if err := e.store.Delete(ctx, t); err != nil {
		return err
	}
	if !recorded {
		e.notifier.OnTupleDelete(ctx, t)
	}
	return nil
}

// CheckDebug performs a check and returns detailed debug info about why it passed or failed.
func (e *Engine) CheckDebug(ctx context.Context, user, relation, object string) (bool, string, error) {
	tm := e.resolveModel(ctx, "")
	if tm == nil {
		return false, "no model loaded (defaultModel is nil)", nil
	}
	if tm.checker == nil {
		return false, "no checker (model loaded but checker is nil)", nil
	}
	if tm.model == nil {
		return false, "no model in tenantModel", nil
	}

	userType, userID, _ := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	// Check model has the type.
	typeDef, ok := tm.model.Types[objectType]
	if !ok {
		types := make([]string, 0, len(tm.model.Types))
		for t := range tm.model.Types {
			types = append(types, t)
		}
		return false, fmt.Sprintf("object type %q not in model (types: %v)", objectType, types), nil
	}

	// Check model has the relation.
	_, ok = typeDef.Relations[relation]
	if !ok {
		rels := make([]string, 0, len(typeDef.Relations))
		for r := range typeDef.Relations {
			rels = append(rels, r)
		}
		return false, fmt.Sprintf("relation %q not on type %q (relations: %v)", relation, objectType, rels), nil
	}

	// Check store has the tuple.
	tuples, _ := e.store.Read(ctx, model.TupleFilter{
		ObjectType: objectType,
		ObjectID:   objectID,
		Relation:   relation,
		UserType:   userType,
		UserID:     userID,
	})

	// Run the actual check.
	allowed, err := tm.checker.Check(ctx, userType, userID, relation, objectType, objectID)
	if err != nil {
		return false, fmt.Sprintf("check error: %v (tuples in store: %d)", err, len(tuples)), err
	}

	return allowed, fmt.Sprintf("allowed=%v, tuples_in_store=%d, user=%s:%s, rel=%s, obj=%s:%s",
		allowed, len(tuples), userType, userID, relation, objectType, objectID), nil
}

// WriteRawTuple writes a tuple directly to the store, bypassing model validation.
// Used by GrantAccess where the control plane already validated the tuple.
// A store failure is returned so callers never assume the local mirror
// converged with the remote grant.
func (e *Engine) WriteRawTuple(ctx context.Context, user, relation, object string) error {
	userType, userID, userRelation := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	t := model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	}

	recorded, err := e.recordTupleWrite(ctx, t)
	if err != nil {
		return err
	}
	if err := e.store.Write(ctx, t); err != nil {
		return fmt.Errorf("write raw tuple %s#%s@%s: %w", object, relation, user, err)
	}
	if !recorded {
		e.notifier.OnTupleWrite(ctx, t)
	}
	return nil
}

// DeleteRawTuple removes a tuple directly from the store, bypassing model validation.
// A store failure is returned so callers never assume the local mirror
// converged with the remote revoke.
func (e *Engine) DeleteRawTuple(ctx context.Context, user, relation, object string) error {
	userType, userID, userRelation := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	t := model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	}

	recorded, err := e.recordTupleDelete(ctx, t)
	if err != nil {
		return err
	}
	if err := e.store.Delete(ctx, t); err != nil {
		return fmt.Errorf("delete raw tuple %s#%s@%s: %w", object, relation, user, err)
	}
	if !recorded {
		e.notifier.OnTupleDelete(ctx, t)
	}
	return nil
}

func (e *Engine) recordTupleWrite(ctx context.Context, t model.Tuple) (bool, error) {
	recorder, ok := e.notifier.(zSync.PrecommitTupleRecorder)
	if !ok {
		return false, nil
	}
	if err := recorder.RecordTupleWrite(ctx, t); err != nil {
		return true, fmt.Errorf("record tuple write %s#%s@%s: %w", t.ObjectKey(), t.Relation, t.UserKey(), err)
	}
	return true, nil
}

func (e *Engine) recordTupleDelete(ctx context.Context, t model.Tuple) (bool, error) {
	recorder, ok := e.notifier.(zSync.PrecommitTupleRecorder)
	if !ok {
		return false, nil
	}
	if err := recorder.RecordTupleDelete(ctx, t); err != nil {
		return true, fmt.Errorf("record tuple delete %s#%s@%s: %w", t.ObjectKey(), t.Relation, t.UserKey(), err)
	}
	return true, nil
}

// ReadTuples returns tuples matching the filter.
func (e *Engine) ReadTuples(ctx context.Context, filter model.TupleFilter) ([]model.Tuple, error) {
	return e.store.Read(ctx, filter)
}

// ListObjects returns all object IDs of the given type that the user has the relation on.
func (e *Engine) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	tm := e.resolveModel(ctx, "")
	if tm == nil || tm.checker == nil {
		return nil, fmt.Errorf("no model loaded")
	}

	userType, userID, _ := check.ParseUserKey(user)
	return tm.checker.ListObjects(ctx, userType, userID, relation, objectType)
}

// ListUsers returns all user keys that have the relation on the object.
func (e *Engine) ListUsers(ctx context.Context, relation, object string) ([]string, error) {
	tm := e.resolveModel(ctx, "")
	if tm == nil || tm.checker == nil {
		return nil, fmt.Errorf("no model loaded")
	}

	objectType, objectID := check.ParseObjectKey(object)
	return tm.checker.ListUsers(ctx, relation, objectType, objectID)
}

// CountTuples returns the number of tuples grouped by object type.
// If the underlying store implements store.TupleCounter, the optimized
// path is used. Otherwise, all tuples are read and counted in memory.
func (e *Engine) CountTuples(ctx context.Context) (map[string]int64, error) {
	if counter, ok := e.store.(store.TupleCounter); ok {
		return counter.CountByObjectType(ctx)
	}

	// Fallback: read all tuples.
	tuples, err := e.store.Read(ctx, model.TupleFilter{})
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64, len(tuples))
	for _, t := range tuples {
		counts[t.ObjectType]++
	}
	return counts, nil
}
