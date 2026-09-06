# Authorization

How a request proves who it is and what it may touch. Read this before adding
any handler that accepts an ID in the URL.

## The two questions

Every request answers two separate questions, and confusing them is how the
rotation IDOR happened:

1. **Authentication** — who is this? Handled by middleware, which puts a user ID,
   org ID and role into the request context.
2. **Ownership** — does the resource in this URL belong to that org? Handled by
   the handler, because only the handler knows what the ID refers to.

Middleware cannot answer the second question. A valid token proves the caller is
*someone*; it says nothing about the UUID they pasted into the path. Until
mid-2026 every rotation handler read `orgID` from the context, used it only to
stamp the audit event, and then acted on whatever secret ID the URL named — so
any account could attach a webhook to another org's secret and trigger it.

## Authentication middleware

| Middleware | Accepts | Used by |
|---|---|---|
| `AuthMiddleware` | Supabase JWT only | Org bootstrap routes (`/orgs`, `/me`) |
| `APITokenMiddleware` | API token only | SDK bulk pull, WebSocket watch |
| `FlexAuthMiddleware` | JWT, falling back to API token | Everything else |

All three populate the same context keys:

```go
model.CtxUserID  uuid.UUID
model.CtxOrgID   uuid.UUID   // absent if the user has no org
model.CtxRole    model.Role
model.CtxEmail   string      // JWT paths only
```

`RequireOrg` runs after them and rejects a caller with no org.

`APITokenMiddleware` and `FlexAuthMiddleware` additionally set `CtxScopes`.
`AuthMiddleware` does not — see [Scopes](#scopes).

## Proving ownership

Two helpers in `internal/handler/secret.go` do the walk. Both write the error
response themselves and return nils, so the caller only checks for nil:

```go
// environment -> project -> org
env, project := h.verifyEnvAccess(w, r, envID)
if env == nil {
    return
}

// secret -> environment -> project -> org
secret, env := h.verifySecretAccess(w, r, secretID)
if secret == nil {
    return
}
```

`verifySecretAccess` is a thin wrapper over `verifyEnvAccess`: it resolves the
secret, then defers to the environment walk. Keeping one implementation of the
org comparison means there is one place to get it right.

Both return `404` when the resource does not exist and `403` when it exists but
belongs to another org. That distinction leaks existence to an attacker holding
a valid ID; it is a deliberate trade for debuggability at this stage, and worth
revisiting — collapsing both to `404` costs nothing but support tickets.

### The rule

> A handler that reads an ID from `chi.URLParam` calls one of these helpers
> before touching the resource or anything reachable from it.

"Anything reachable from it" is the part that is easy to miss. `GET
/secrets/{sid}/rotation` does not read the secret — it reads the *schedule*. It
still needs the secret's ownership checked, because the schedule is only
reachable through the secret.

When the route is keyed by a child resource, resolve upward first:

```go
sched, err := h.Store.GetRotationScheduleByID(r.Context(), schedID)
if err != nil || sched == nil {
    respond.Error(w, http.StatusNotFound, "rotation schedule not found")
    return
}
if secret, _ := h.verifySecretAccess(w, r, sched.SecretID); secret == nil {
    return
}
```

## Scopes

A role says what a *person* may do. A scope says how much of that authority a
particular *credential* carries. The authority of a request is the intersection
of the two, and `rbac.Allows` is the one function that computes it:

```go
func Allows(role model.Role, scopes []string, perm Permission) bool {
	return HasPermission(role, perm) && ScopesAllow(scopes, perm)
}
```

Scopes and permissions share a vocabulary on purpose — a scope names a
permission — so there is no mapping table to drift.

### nil is not empty

`ScopesAllow` treats the two differently, and the distinction is the whole
design:

| Scopes | Means | Result |
|---|---|---|
| `nil` | Not scope-limited — a user JWT | Every permission the role grants |
| `[]string{}` | A token granted nothing | Nothing |
| `["secrets:read"]` | A token granted one scope | Only that, and only if the role has it |

`AuthMiddleware` sets no scopes at all, so a browser session is bounded by its
role alone. `tokenContext` always sets them, substituting an empty slice for a
nil column, so a token can never fall through into the unrestricted case.

### Where the check happens

Two layers, and a request must pass both:

1. **`middleware.RequireScope(perm)` at the router.** Every route declares the
   scope it needs at registration, so a route is protected by existing rather
   than by a handler remembering. When you add a route, add its scope.
2. **Role checks in the handler.** The handler knows the resource and whether
   its environment is protected, which the router cannot.

The secret helpers take scopes directly, so a single call covers both halves:

```go
if !rbac.CanReadSecret(getRole(r), getScopes(r), env.IsProtected) {
```

For anything else, `h.allows(r, perm)` is the handler-side equivalent of
`rbac.Allows`.

### The role snapshot

`api_tokens.role` records the role its creator held when the token was minted.
The effective role of a request is the **lower** of that snapshot and the user's
current role:

```go
ctx = context.WithValue(ctx, model.CtxRole, rbac.LowerRole(token.Role, user.Role))
```

Each bound closes a different hole. Before this, the role was read live from the
users table on every request, so:

- **Promotion leaked backwards.** A token minted by a developer silently gained
  owner authority the moment that person was promoted. The snapshot caps it.
- **Demotion did nothing.** A token minted by an owner kept owner authority
  after that person was demoted to reader. The live role caps it.

A token also cannot be created with a scope its creator's role does not grant —
`CreateAPIToken` rejects that with `403` rather than issuing a credential whose
scopes overstate what it can do.

Unknown scopes are rejected at creation too. Silently dropping a typo'd scope
would produce a token that looks like it grants something it does not.

## Roles and permissions

Ownership says the resource is yours. Role says what you may do with it.
`internal/rbac` holds the matrix:

| | Read | Write | Delete | Members | Billing |
|---|:-:|:-:|:-:|:-:|:-:|
| Owner | ✓ | ✓ | ✓ | ✓ | ✓ |
| Admin | ✓ | ✓ | ✓ | ✓ | — |
| Developer | ✓ | ✓ | — | — | — |
| Reader | ✓ | — | — | — | — |

Protected environments override the table: only Owner and Admin may read or
write, whatever the role column says. That is why the read check takes the flag:

```go
if !rbac.CanReadSecret(getRole(r), getScopes(r), env.IsProtected) {
    respond.Error(w, http.StatusForbidden, "insufficient permissions for this environment")
    return
}
```

Call it *after* the ownership check. Checking the role first tells an attacker
whether their role would have sufficed, which is a small leak but a free one to
avoid.

`middleware.RequireRole` still exists and is wired to nothing. Either use it or
delete it — a helper that looks like enforcement but is never called reads as
protection during review and is worse than its absence.

## Checklist for a new handler

1. Register it with `middleware.RequireScope(...)` naming the scope it needs.
2. Parse the ID; `400` on a malformed UUID.
3. Call `verifyEnvAccess` or `verifySecretAccess`; return on nil.
4. Check the role with the appropriate `rbac` helper, passing `getScopes(r)`.
5. Do the work.
6. Write an audit event.
7. Make sure the response contains no credential — see the `rotationView`
   pattern in `internal/handler/rotation.go` for redacting a config blob.

Step 1 is the one that is easy to skip, because the route works without it. The
audit in `internal/rbac/rbac_test.go` and the route scan in the P0-4 commit
message are how we check nothing slipped through.
