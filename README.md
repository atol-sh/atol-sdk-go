# Atol SDK for Go

Go SDK for [Atol](https://atol.sh) — authentication and authorization for developers who ship. One SDK, one dashboard. Embeds JWT validation, OPA policy evaluation, and Zanzibar relationship checks in-process for <250us authorization decisions with no network I/O on the hot path.

The SDK runs inside your service and handles authentication and authorization locally. It connects to [atol.sh](https://atol.sh) at startup to pull your configuration, then makes all decisions in-memory. The source is open so you can see exactly what runs in your infrastructure.

```go
import sdk "atol.sh/sdk-go"
```

## Getting Started

### 1. Create an Atol account

Sign up at [atol.sh](https://atol.sh). Create an organization — this is your tenant in Atol and the scope for all users, roles, and policies.

### 2. Get your credentials

In the dashboard sidebar, open **APIs** and click **New API Key** to create a
server-to-server key (HMAC-signed). You'll need:

| Credential | Where to find it | What it's for |
|------------|-----------------|---------------|
| **Control plane URL** | Settings > General (your org's subdomain) | `https://<org-slug>.atol.sh` (`ControlPlaneURL` in the SDK config); also your OIDC issuer |
| **Org ID** | Settings > General (ORG ID) | Identifies your organization (`StoreID` in the SDK config) |
| **Key ID** | APIs > New API Key | Publishable credential (`KeyID` in the SDK config) |
| **Secret Key** | APIs > New API Key | Private credential, shown once (`SecretKey` in the SDK config) |
| **JWKS URL** | Auto-derived from `ControlPlaneURL` | Validates user JWTs; override via `JWKSUrl` only if your issuer differs |

### 3. Define your authorization model

In the dashboard, go to **Authorization > Model** and define your resource types and relationships:

```yaml
types:
  user: {}

  organization:
    relations:
      owner:
        types: [user]
      member:
        types: [user]

  document:
    relations:
      org:
        types: [organization]
      editor:
        union:
          - from: org
            lookup: owner
          - from: org
            lookup: member
      viewer:
        union:
          - editor
```

Each relation either lists the subject types that can be assigned directly
(`types: [user]`) or derives from other relations (`union:`). A union entry
that is a plain string references another relation on the same type; a
`{from, lookup}` entry walks a linked object (here: a document's `org`) and
checks a relation there.

### 4. Write your policy

In **Authorization > Rules**, write Rego rules that use `zanzibar.check()` as a built-in.
The engine evaluates these query paths, in order, and uses the first one that
is defined:

1. `data.atol.access.<resource_type>.allow`
2. `data.atol.allow`
3. `data.atol.access.<resource_type>.decision`
4. `data.atol.decision`

So your policy must live under `package atol` (or `package atol.access.<type>`),
and the input carries `input.user`, `input.relation`, and `input.object`
(plus `input.resource_type`, `input.resource_id`, and the enriched fields
from `Authorize()` such as `input.plan` and `input.mfa_verified`):

```rego
package atol

import rego.v1

default allow := false

allow if {
  input.relation == "editor"
  zanzibar.check(input.user, "editor", input.object)
}

allow if {
  input.relation == "viewer"
  zanzibar.check(input.user, "viewer", input.object)
}
```

If no query path is defined for an input, the SDK falls back to a bare
Zanzibar relationship check. An evaluation error never falls back — it is
surfaced to the caller and the request is denied.

### 5. Install the SDK

```bash
go get atol.sh/sdk-go
```

### 6. Initialize and bootstrap

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    sdk "atol.sh/sdk-go"
    atolmw "atol.sh/sdk-go/middleware"
)

func main() {
    atol, err := sdk.New(sdk.Config{
        ControlPlaneURL: "https://acme.atol.sh", // your per-tenant subdomain (org slug)
        KeyID:     os.Getenv("ATOL_KEY_ID"),
        SecretKey: os.Getenv("ATOL_SECRET_KEY"),
        StoreID:         os.Getenv("ATOL_ORG_ID"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer atol.Close()

    // Bootstrap: pulls your model, tuples, and policy bundle from atol.sh.
    if err := atol.Bootstrap(context.Background()); err != nil {
        log.Fatal(err)
    }

    // Middleware validates JWTs (issued by atol.sh) and sets the principal in context.
    mux := http.NewServeMux()
    mux.Handle("/api/", atolmw.HTTPMiddleware(atol)(apiHandler))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Set your credentials as environment variables — never hardcode them:

```bash
export ATOL_KEY_ID=atol_kid_...        # from dashboard APIs > New API Key
export ATOL_SECRET_KEY=atol_sk_...     # shown once on creation, never again
export ATOL_ORG_ID=org_01JQXYZ      # from dashboard Settings > General
```

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  Atol (managed control plane)                       │
│  Dashboard:     app.atol.sh                         │
│  SDK endpoint:  <org>.atol.sh                       │
│                                                     │
│  You configure:                                     │
│    Users, orgs, roles → managed via dashboard/API   │
│    Authorization model → YAML in dashboard          │
│    Policies → Rego in dashboard                     │
│    Audit logs → viewable in dashboard               │
└──────────────┬──────────────────────┬───────────────┘
               │ bootstrap            │ sync (streaming)
               │ (model + tuples +    │ (live mutations)
               │  policy bundle)      │
               ▼                      ▼
┌─────────────────────────────────────────────────────┐
│  Your Service (with atol-sdk-go embedded)           │
│                                                     │
│  ├─ Token Validator  (JWKS from atol.sh)            │
│  ├─ OPA Engine       (policy bundle from bootstrap) │
│  ├─ Zanzibar Engine  (tuples from bootstrap + sync) │
│  ├─ Decision Logger  (async → atol.sh)              │
│  └─ State Sync       (streams mutations)            │
│                                                     │
│  sdk.Check(ctx, "editor", "doc:readme")  →  <250us  │
└─────────────────────────────────────────────────────┘
```

**Startup:** `Bootstrap()` pulls the authorization model, relationship tuples, and compiled OPA policy bundle from atol.sh via gRPC.

**Runtime:** `Check()` / `Can()` / `Authorize()` evaluate locally in memory. No network calls on the hot path.

**Live sync:** After bootstrap, the SDK streams mutations (tuple writes/deletes, model updates, policy updates) in real-time. When you grant a role in the dashboard, connected SDKs see it within milliseconds.

**Decision logs:** Authorization decisions are buffered locally and flushed asynchronously to atol.sh for the audit timeline.

**JWT validation:** User tokens issued by atol.sh are validated locally via JWKS. The SDK caches the signing keys and refreshes them automatically.

### What the SDK stores (and what it doesn't)

Everything the SDK holds is an **in-memory replica** of control-plane state. There is no SDK-side
database, nothing is written to disk, and there is no store to configure. If the process restarts,
it rebuilds on the next `Bootstrap()` and replays anything it missed — so there is nothing local to
back up.

| Held in the SDK | Source of truth | Kept fresh by |
|-----------------|-----------------|---------------|
| Relationship tuples + authorization model | atol.sh control plane | bootstrap snapshot, then live mutation stream |
| OPA policy bundle + policy data | atol.sh control plane | bootstrap, then live mutation stream |
| Revoked-session list (CRL) | atol.sh control plane | polled every 30s |
| JWKS signing keys | atol.sh control plane | fetched on demand, auto-refreshed |
| Decision logs | not stored — shipped out | async flush to atol.sh; dropped if the buffer is full |
| Materialized tuples | **your** application's database | your `RegisterMaterializer` callbacks; **never sent to atol.sh** |

Two consequences worth knowing:

- **The store is deliberately not pluggable** (there is no `WithStore` option). The in-memory store
  is a throwaway replica of control-plane state; injecting your own backend would mean
  reimplementing the bootstrap and sync contract. App-specific relationships have their own path in —
  `RegisterMaterializer` and [context tuples](#context-tuples) — and that data stays in your process.
- **Your data stays yours.** A decision is computed locally and never round-trips. Only writes
  (grant/revoke) and audit events go to the control plane; materialized tuples derived from your own
  data never leave the process.

## Authentication

Atol is also your identity provider. Your frontend redirects users to atol.sh for login (OIDC Authorization Code flow), and your backend validates the resulting JWT with the SDK middleware.

**Frontend** — redirect to Atol login:
```
https://acme.atol.sh/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://yourapp.com/callback&
  response_type=code&
  scope=openid profile email
```

Configure your OIDC client in the dashboard under **Settings > Authentication**. You'll get a `client_id` and can set allowed redirect URIs.

**Backend** — the SDK middleware handles the rest:
```go
// Middleware extracts the Bearer token, validates it against atol.sh JWKS,
// and sets the authenticated principal in the request context.
handler = atolmw.HTTPMiddleware(atol)(handler)

// In your handler, the principal is available:
p, _ := sdk.UserFromContext(ctx)
fmt.Println(p.UserID)     // "usr_01JQXYZ"
fmt.Println(p.Email)      // "user@example.com"
fmt.Println(p.OrgID)      // "org_01JQXYZ"
fmt.Println(p.Roles)      // ["admin"]
fmt.Println(p.Plan)       // "pro"
fmt.Println(p.AuthMethod) // "oidc"
```

## Authorization

### Check permissions

```go
// From request context (uses the principal set by middleware):
allowed, err := atol.Check(ctx, "editor", "document:doc-123")

// Explicit user + relation + object:
allowed, err := atol.Can(ctx, "user:usr_01JQXYZ", "owner", "organization:org-456")

// Full OPA evaluation with enriched context (roles, plan, auth method, MFA):
decision, err := atol.Authorize(ctx, "publish", "post:post-789")
if decision.Allow {
    // proceed
}
```

### Grant and revoke access

Manage relationships through the [Atol dashboard](https://app.atol.sh) or API:

```bash
# Grant editor access via API
curl -X POST https://acme.atol.sh/api/v1/access/grant \
  -H "X-Atol-Key: $ATOL_KEY_ID" \
  -d '{"org_id": "org_01JQXYZ", "user": "user:usr_abc", "relation": "editor", "object": "document:doc-123"}'
```

Changes sync to connected SDKs in real-time — no restart needed.

### Context tuples

Overlay ephemeral relationships for a single check without persisting them:

```go
allowed, err := atol.Can(ctx, "user:alice", "viewer", "patient:p-123",
    sdk.WithContextTuples(
        model.Tuple{User: "patient:p-123", Relation: "provider", Object: "user:alice"},
    ),
)
```

### Materializers

Register callbacks that produce tuples from your app's own data at bootstrap time. Useful for relationships you already track in your database:

```go
atol.RegisterMaterializer("org-hierarchy", func(ctx context.Context) ([]model.Tuple, error) {
    // Query your database for org membership and return as tuples.
    // These tuples live in SDK memory only — never sent to atol.sh.
    return tuples, nil
})
```

## Middleware

Built-in middleware for HTTP, gRPC, and Connect-go:

```go
import atolmw "atol.sh/sdk-go/middleware"

// net/http
handler = atolmw.HTTPMiddleware(atol)(handler)

// gRPC
grpc.NewServer(grpc.UnaryInterceptor(atolmw.GRPCUnaryInterceptor(atol)))

// Connect-go
connect.WithInterceptors(atolmw.ConnectInterceptor(atol))
```

## Sender-constrained tokens (DPoP)

The SDK accepts both `Bearer` and `DPoP` authorization schemes. For a DPoP
request it validates the proof JWT and binds it to the access token's `cnf.jkt`,
so a stolen token cannot be replayed without the matching proof key. DPoP proof
validation runs only on the HTTP middleware path (the gRPC and Connect
interceptors reject DPoP-bound tokens with an explicit error). Set
`Config.RequireDPoP = true` to reject plain Bearer tokens entirely once all your
clients are DPoP-capable.

## Device intelligence

With `Config.Device.Enabled = true`, the middleware reads the `X-Atol-Device-Id`
header (set by the Atol client JS SDK) and exposes device signals to your Rego
policies as `input.device.*` — so a policy can deny detected bots or
high-anomaly sessions even when valid credentials are presented. The
auto-generated default policy already enforces this:

```rego
device_blocked if input.device.signals.bot == true
device_blocked if input.device.signals.anomaly_score > data.atol.device_max_anomaly_score
```

The scoring itself happens in the control plane; the SDK only carries the
signals. `atol.DriftDetector()` additionally compares each authenticated
request against the device bound to its session and reports divergences (a
changed user-agent family, or a missing fingerprint on a script-initiated call)
to the control plane without blocking the request.

## Zero-knowledge encryption

The `encryption` package derives a Key Encryption Key from a user password
(Argon2id over an HKDF-SHA256 salt bound to the user and client) and wraps or
unwraps a Data Encryption Key with AES-256-GCM. The password and DEK never
leave the process; only the wrapped DEK is stored.

```go
kek, err := encryption.DeriveKEK(password, userID, clientID)
dek, err := encryption.UnwrapDEK(wrappedDEKBase64, kek)
```

## SDK Configuration

```go
sdk.Config{
    // Required
    ControlPlaneURL: "https://acme.atol.sh", // <org-slug>.atol.sh; also the OIDC issuer + JWKS base
    KeyID:     "atol_kid_...",          // Publishable key ID from the dashboard
    SecretKey: "atol_sk_...",           // Secret key (shown once on creation)
    StoreID:         "org_01JQXYZ",          // Your org ID from the dashboard

    // Optional
    Issuer:                   "",            // Expected JWT iss claim. Defaults to ControlPlaneURL
    Audience:                 "",            // Expected JWT aud claim. When set, tokens must carry it
    JWKSUrl:                  "",            // Auto-derived: ControlPlaneURL + /.well-known/jwks.json
    ZanzibarModelPath:        "",            // Local model YAML loaded at New(); bootstrap can replace it
    BootstrapTimeout:         10 * time.Second, // Applied to Bootstrap() via context timeout
    DisableSync:              false,         // Zero value = live mutation streaming ON
    DecisionLogFlushInterval: 5 * time.Second,
    DecisionLogBufferSize:    10000,
    RequireDPoP:              false,         // true = reject Bearer tokens, mandate DPoP proofs
    Device:                   device.Config{Enabled: true}, // Inject X-Atol-Device-Id into input.device.*
}
```

`Issuer` covers the case where the control plane's network address differs
from the token issuer (e.g. Docker: `ControlPlaneURL=host.docker.internal:9080`,
`Issuer=localhost:9080`). `Device` is the `atol.sh/sdk-go/device` package.

Inject a logger to surface background failures (CRL refresh, decision log
flush, sync disconnects) — the default is a no-op logger:

```go
atol, err := sdk.New(cfg, sdk.WithLogger(zapLogger))
```

## Packages

| Package | Import | Purpose |
|---------|--------|---------|
| Root | `atol.sh/sdk-go` | `sdk.New()`, `Check()`, `Can()`, `Authorize()`, `Bootstrap()` |
| Middleware | `atol.sh/sdk-go/middleware` | HTTP, gRPC, Connect-go auth middleware |
| Testing | `atol.sh/sdk-go/atoltest` | Test engine, token factory, context builder, mock OIDC server |
| Zanzibar | `atol.sh/sdk-go/zanzibar` | Relationship engine: model, check, tuple store |
| Policy | `atol.sh/sdk-go/policy/engine` | OPA engine with `zanzibar.check()` built-in |
| Identity | `atol.sh/sdk-go/identity` | JWT claims types, JWKS fetcher |
| Device | `atol.sh/sdk-go/device` | Device-intelligence context + session drift detection |
| Encryption | `atol.sh/sdk-go/encryption` | Zero-knowledge KEK derivation + DEK wrap/unwrap |
| Bootstrap | `atol.sh/sdk-go/bootstrap` | State initialization from atol.sh |
| Decision | `atol.sh/sdk-go/decision` | Async decision log buffer + sink |
| Sync | `atol.sh/sdk-go/sync` | Live mutation streaming from atol.sh |

## Testing

The `atoltest` package provides everything you need to test code that depends on the Atol SDK — no control plane, no external services, no Docker.

```go
import "atol.sh/sdk-go/atoltest"
```

### Unit tests

Create a test engine with your authorization model, pre-populate tuples, and run checks:

```go
func TestDocumentAccess(t *testing.T) {
    engine := atoltest.NewEngine(t,
        atoltest.WithModelFile("testdata/model.yaml"),
        atoltest.WithTuples(
            atoltest.Tuple{User: "user:alice", Relation: "owner", Object: "document:doc-1"},
            atoltest.Tuple{User: "user:bob", Relation: "editor", Object: "document:doc-1"},
        ),
    )

    ctx := atoltest.Context().WithUser("alice").Build()

    allowed, err := engine.Check(ctx, "viewer", "document:doc-1")
    if err != nil {
        t.Fatal(err)
    }
    if !allowed {
        t.Error("alice should be a viewer (owner → viewer via union)")
    }
}
```

The engine returned by `NewEngine` embeds `*sdk.Atol` — all SDK methods (`Check`, `Can`, `Authorize`, `GrantAccess`, `RevokeAccess`, `RegisterMaterializer`, etc.) work directly on it. No control plane connection is needed; `GrantAccess` and `RevokeAccess` write to the local in-memory store.

### Tuple helpers

```go
// One at a time.
engine.Grant("user:alice", "editor", "document:doc-1")
engine.Revoke("user:alice", "editor", "document:doc-1")

// Bulk setup — replaces TestMain boilerplate.
engine.GrantAll([]atoltest.Tuple{
    {User: "user:alice", Relation: "owner", Object: "org:acme"},
    {User: "user:bob", Relation: "member", Object: "org:acme"},
    {User: "user:charlie", Relation: "editor", Object: "document:doc-1"},
})

// Or use GrantAccess/RevokeAccess — they work locally, no control plane needed.
engine.GrantAccess(ctx, "user:alice", "owner", "document:doc-1")
```

### Context builder

Build authenticated request contexts without hand-crafted helpers:

```go
ctx := atoltest.Context().
    WithUser("usr_123").
    WithEmail("user@example.com").
    WithOrg("acme").
    WithRoles("admin", "editor").
    WithPlan("pro").
    WithMFA().
    WithAuthMethod("passkey").
    WithIdentity("oidc://acme.atol.sh/abc", "oidc").
    Build()
```

Use `FromContext` to enrich an existing context:

```go
ctx := atoltest.FromContext(r.Context()).WithUser("alice").Build()
```

### Real JWT validation

Test tokens mint real RS256-signed JWTs that pass through the SDK's actual `TokenValidator`. The test engine runs a local JWKS server automatically.

```go
func TestHTTPHandler(t *testing.T) {
    engine := atoltest.NewEngine(t, atoltest.WithModelFile("testdata/model.yaml"))
    engine.Grant("user:alice", "editor", "document:doc-123")

    token := engine.Tokens().MintToken(
        atoltest.WithSubject("alice"),
        atoltest.WithEmail("user@example.com"),
        atoltest.WithOrgID("acme"),
        atoltest.WithRoles("admin"),
    )

    // Use the real SDK middleware — no bypass flags.
    handler := atolmw.HTTPMiddleware(engine.Atol)(myHandler(engine.Atol))

    r := httptest.NewRequest("GET", "/api/docs/doc-123", nil)
    r.Header.Set("Authorization", "Bearer "+token)
    w := httptest.NewRecorder()
    handler.ServeHTTP(w, r)

    if w.Code != http.StatusOK {
        t.Errorf("status = %d, want 200", w.Code)
    }
}
```

Token options: `WithSubject`, `WithEmail`, `WithOrgID`, `WithRoles`, `WithPlan`, `WithAuthMethod`, `WithMFA`, `WithIdentity`, `WithTrustDomain`, `WithAudience`, `WithExpiry`, `WithJTI`, `WithAuthTime`.

### Test auth middleware

For handler tests that don't need real JWT validation, inject a principal directly:

```go
handler := atoltest.AuthMiddleware("usr_test", "test@example.com",
    atoltest.WithMiddlewareOrg("acme"),
    atoltest.WithMiddlewareRoles("admin"),
)(myHandler)
```

### Audience validation

```go
engine := atoltest.NewEngine(t,
    atoltest.WithModel(model),
    atoltest.WithTestAudience("https://api.example.com"),
)

// Tokens must include the matching audience.
token := engine.Tokens().MintToken(
    atoltest.WithSubject("alice"),
    atoltest.WithAudience("https://api.example.com"),
)
```

### Shared token factory

When multiple engines need to trust the same JWKS (e.g., testing multi-service auth):

```go
tf := atoltest.NewTokenFactory(t)

engine1 := atoltest.NewEngine(t, atoltest.WithModel(model), atoltest.WithTokenFactory(tf))
engine2 := atoltest.NewEngine(t, atoltest.WithModel(model), atoltest.WithTokenFactory(tf))

token := tf.MintToken(atoltest.WithSubject("shared-user"))
// Both engines accept this token.
```

### E2E tests (Cypress / browser)

For browser-based E2E tests that need an HTTP token endpoint, use `MockOIDCServer`:

```go
func TestMain(m *testing.M) {
    srv := atoltest.NewMockOIDCServer(t)
    // srv.URL() → "http://127.0.0.1:<port>"
    // Endpoints:
    //   POST /oauth/token          — mint a JWT
    //   GET  /.well-known/jwks.json — public key set
    //   GET  /.well-known/openid-configuration
    //   GET  /health
}
```

Or run the standalone server as a drop-in replacement for a mock-auth service:

```bash
go run atol.sh/sdk-go/cmd/atoltest-server -addr :3100
```

Your Cypress tests can then fetch tokens via HTTP:

```typescript
cy.request({
    method: 'POST',
    url: 'http://localhost:3100/oauth/token',
    body: { sub: 'e2e-user', email: 'e2e@test.example.com' },
}).then((resp) => {
    const token = resp.body.access_token;
    // Use token in Authorization header
});
```

### Engine options reference

| Option | Purpose |
|--------|---------|
| `WithModel(yaml)` | Load a Zanzibar model from bytes |
| `WithModelFile(path)` | Load a Zanzibar model from a file |
| `WithTuples(tuples...)` | Pre-populate the tuple store |
| `WithPolicy(bundle, data)` | Load an OPA policy bundle |
| `WithTestAudience(aud)` | Require JWT audience validation |
| `WithTokenFactory(tf)` | Share a JWKS across multiple engines |

## Requirements

- Go 1.26+
- [Atol account](https://atol.sh) (15-day free trial)

## License

Apache 2.0
