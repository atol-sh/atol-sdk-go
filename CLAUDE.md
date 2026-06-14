# Atol SDK for Go

Embeddable Go SDK for [Atol](https://atol.sh) -- identity + authorization. JWT validation, OPA policy eval, and Zanzibar relationship checks in-process. No network I/O on the hot path.

- **Repo:** `atol-sh/atol-sdk-go`
- **Module:** `atol.sh/sdk-go` / `import sdk "atol.sh/sdk-go"`
- **License:** Apache 2.0, Go 1.26+

## Output Control

- Answer starts on line 1. No openers ("Sure!", "Great question!", "Absolutely!").
- No closings ("Hope this helps!", "Let me know!"). Stop when done.
- No restating the question. Execute immediately.
- No "As an AI..." framing. No unnecessary disclaimers.
- No unsolicited suggestions beyond requested scope.
- Corrections from user become ground truth. Never agree with incorrect statements.
- ASCII only. No em dashes, smart quotes, or Unicode bullets. Plain hyphens and straight quotes.
- If unsure: say so. Never guess file paths, function names, or API endpoints.
- User instructions override this file.

## Workflow

- Read before writing. Understand existing code before modifying.
- No redundant file reads. Read each file once per session.
- One focused coding pass. No write-delete-rewrite cycles.
- Test once, fix if needed, verify once.
- Prefer editing over rewriting whole files.

## Related Projects

This SDK embeds the engines and consumes the API served by the Atol control
plane ([atol.sh](https://atol.sh)). The control-plane repository, its
implementation spec, and the canonical proto definitions are maintained
separately; consult them before making architectural decisions.

## Architecture

```
atol.sh (control plane) → bootstrap + sync → atol-sdk-go (embedded)
├─ Token Validator    (JWKS, cached, auto-refresh)
├─ OPA Engine         (embedded, zanzibar.check() built-in)
├─ Zanzibar Engine    (in-memory, sub-ms checks)
├─ Device Context     (X-Atol-Device-Id → OPA input.device.*)
├─ Decision Logger    (async ring buffer → control plane)
├─ Session Validator  (CRL polling, revoked JTI set)
└─ State Sync         (streaming mutations)
```

**Request flow:** Middleware → Bearer extraction → JWKS validation → session CRL check → Principal in context → Device context → Check/Can/Authorize (single OPA eval <250us with zanzibar.check()) → async decision log → handler.

**Key concepts:**
- Two-layer principal: `user:alice` (scheme-agnostic) + `identity:oidc://...` (scheme-specific)
- Three auth APIs: `Check(ctx, relation, object)`, `Can(ctx, user, relation, object)`, `Authorize(ctx, action, resource)`
- Three tuple patterns: stored (synced), context (ephemeral per-check), materialized (app DB)
- HMAC-signed requests: secret never transmitted, only signature
- Bootstrap then stream: snapshot on startup, mutations forever

## Code Principles

1. **Hot path.** Authorization flow must be sub-millisecond. No allocations in tight loops. No network I/O during Check/Can/Authorize.
2. **Deny by default.** No principal → deny. Eval error → deny. Missing model → pure Zanzibar fallback. Never fail open.
3. **600-line file limit.** Split by responsibility.
4. **Thread safety.** All engines use `sync.RWMutex`. Safe for concurrent goroutines.
5. **Graceful lifecycle.** `New()` → `Bootstrap()` → use → `Close()`.
6. **Minimal deps.** Prefer stdlib. License: Apache 2.0 / MIT / BSD only. `go mod tidy` after every change.

## Go Standards (project-specific deviations from defaults)

Follow Effective Go and Google Go Style Guide. These are the project-specific rules:

- **Packages:** no stutter. `middleware.HTTP` not `middleware.HTTPMiddleware`. No `util`/`helper`/`common`.
- **Receivers:** 1-2 letter abbreviation (`e` for Engine, `s` for Store). Never `self`/`this`.
- **Errors:** lowercase, no punctuation: `fmt.Errorf("compute hash: %w", err)`. Don't log and return -- do one or the other. Sentinels for programmatic checks.
- **Security errors deny by default.** Auth check error → deny access. Generic errors to callers (`ErrAccessDenied`). Never leak internal details.
- **Functional options** for complex config: `type Option func(*options)` with unexported struct.
- **Test format:** table-driven, `-race`, `t.Helper()`, `t.Cleanup()`, `got X, want Y` messages.
- **Logging:** `zap.Logger` only. Fields: `tenant_id`, `user_id`, `request_id`, `trace_id`, `duration_ms`, `error`. Never log secrets/tokens/PII.

## Security

- `crypto/rand` only for security values. Never `math/rand`.
- HMAC-SHA256 for signing. `hmac.Equal()` for verification, never `==`.
- TLS 1.2+ minimum. Never `InsecureSkipVerify: true`.
- Never log: API keys, secret keys, tokens, HMAC signatures, JWT payloads.
- Validate all external input at boundaries. Bound all sizes. Check integer overflow (`internal/safeconv`).

## File Organization

```
atol-sdk-go/
├─ atol.go, check.go, config.go, principal.go  # Core SDK
├─ auth.go, session_validator.go                # Token + session validation
├─ decision_types.go, materializer.go           # Decision + materializer types
├─ middleware/        # HTTP, gRPC, Connect-go, device middleware
├─ identity/          # AtolClaims, JWKS fetcher
├─ zanzibar/          # Engine, check/, model/, store/
├─ policy/engine/     # OPA engine + zanzibar.check() built-in
├─ device/            # Device context, middleware, OPA input injection
├─ decision/          # Async decision logger, ring buffer, RPC sink
├─ atoltest/          # Test engine, token factory, context builder, mock OIDC
├─ cmd/atoltest-server/  # Standalone mock OIDC server for E2E
├─ bootstrap/         # Snapshot fetch from control plane
├─ sync/              # StreamMutations client
├─ gen/               # Generated gRPC stubs (buf generate)
└─ proto/             # Proto definitions (SDK subset)
```

## OPA Policy Input Schema

`Authorize()` builds this input:

```json
{
  "user": "user:alice", "action": "edit", "resource": "document:456",
  "org": "acme", "roles": ["team_lead"], "plan": "pro",
  "auth_method": "passkey", "mfa_verified": true,
  "trust_domain": "acme.atol.sh", "client_ip": "10.0.1.42",
  "auth_time_ns": 1711900000000000000,
  "identity_id": "identity:oidc://acme.atol.sh/abc123", "identity_scheme": "oidc",
  "device": { "id": "device:fp_...", "known": true, "confidence": 0.96, "signals": { "bot": false, "vpn": false } }
}
```

**Evaluation order:** `data.atol.access.<type>.allow` → `data.atol.allow` → `data.atol.access.<type>.decision` → `data.atol.decision` → pure Zanzibar (no OPA bundle).

## Running

```bash
go test -race ./...              # All tests with race detector
buf lint proto/                  # Lint protos
buf generate proto/              # Regenerate gRPC stubs
```

## Key Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Zanzibar store | In-memory | Sub-ms checks, no I/O on hot path |
| Policy engine | OPA + zanzibar.check() | Apache 2.0, single eval |
| Token validation | JWKS cached | Auto-refresh, no network steady state |
| Control plane auth | HMAC-SHA256 | Secret never transmitted |
| Decision logging | Async ring buffer | Never blocks hot path |
| Tuple persistence | Write-through | Local store immediate, sync to others |
| Session revocation | CRL polling 30s | O(1) check, bounded staleness |
