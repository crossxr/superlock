# Developer documentation

Internal notes on how SuperLock works — the reasoning behind the design, the
invariants each subsystem depends on, and the traps that have already bitten us.
User-facing documentation lives in `frontend/app/docs/content/`; keep the two in
sync when behaviour changes.

Write for the person who has to change this code in six months and does not
remember why it is shaped this way. Prefer explaining *why* over *what* — the
code already says what.

## Contents

| Document | Covers |
|---|---|
| [authorization.md](authorization.md) | How a request is authenticated and how ownership is proven. Read this first. |
| [rotation.md](rotation.md) | The rotation worker, the webhook contract, and why the payload carries no secret value. |
| [egress-security.md](egress-security.md) | `netguard` — outbound requests to customer-controlled destinations. |
| [websockets.md](websockets.md) | The invalidation stream, its authorization, and the concurrency rules the hub depends on. |

## Not yet documented

These subsystems are in the codebase but have no developer notes. Several have
known defects recorded in `PLAN.md` at the repo root; do not treat their current
behaviour as intended until they are fixed and documented.

- Audit log and the HMAC chain — **currently unverifiable**, see PLAN.md P0-6
- Dynamic secrets (Postgres / MySQL leases)
- Approvals — **no write path creates one**, see PLAN.md P1
- Billing, plan gating and limits
- Secret references (`${secret:KEY}`)
- Secret sharing

## Conventions

**Security fixes get a regression test.** Not a test that the fix compiles — a
test that fails against the original code. When a bug was a race or a panic,
verify the test reproduces it before you keep it: revert the fix, watch the test
fail, restore the fix. A test that never could have caught the bug is worse than
no test, because it reads like coverage.

**Anything customer-supplied that we connect to goes through `netguard`.** URLs,
DSNs, hostnames. No exceptions, no direct `http.DefaultClient`.

**Credentials never round-trip through the API.** If a config blob holds a DSN, a
signing secret or a header value, it is `json:"-"` on the model and the handler
builds an explicit redacted view. Adding a field to such a blob means revisiting
the view.

**Ownership is proven, never assumed.** Any handler that takes an ID from the URL
resolves it to an org and compares. See [authorization.md](authorization.md).
