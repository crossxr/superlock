# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

This is a monorepo for **SuperLock**, a zero-trust secrets management and dynamic configuration platform.

```
.
├── superlock/
│   ├── backend/   # Go 1.23+ REST & WebSocket API (Chi, pgx, Redis) — module github.com/nan0/backend
│   ├── cli/       # SuperLock CLI (Node.js, published as @superlock/cli / bin `superlock`)
│   ├── sdk/       # Client SDKs: go/, node/ (@superlock/node), python/ (superlock-sdk), java/
│   └── docs/      # setup.md (env setup/deploy) and test.md (manual test walkthrough)
├── frontend/      # Next.js 15 dashboard — this is a separate git submodule (repo: exprays/customkeys-web)
├── agents.md      # Full LLM/agent reference: data model, REST API, RBAC, plan tiers, SDK usage
└── history/       # Old planning docs — gitignored, not part of the shipped project
```

`agents.md` is the authoritative reference for the product/data model, full REST API surface, plan-tier feature matrix, and SDK usage patterns — read it before making API or billing-tier changes rather than re-deriving that context from code.

`frontend/` is a **git submodule**, not part of this repo's own history — commits there belong to the `exprays/customkeys-web` repo and must be made/pushed from inside that submodule.

## Commands

### Backend (`superlock/backend`)

```bash
cd superlock/backend
go mod download
go run ./cmd/server              # starts on :8080, runs DB migrations automatically on boot
go build ./...
go test ./...                    # run all tests
go test ./internal/rbac/...      # single package
go test ./internal/rbac/ -run TestHasPermission   # single test
```

There is no linter config (`.golangci.yml`) in the repo — use `go vet ./...` / `gofmt` for hygiene checks.

Local dev needs `superlock/backend/.env` (copy from `.env.example`) with `DATABASE_URL` (Supabase Postgres), `SUPABASE_URL`, `ENCRYPTION_KEY`, `AUDIT_HMAC_KEY` at minimum. See `superlock/docs/setup.md` for how to generate keys and provision Supabase/Upstash.

Deploy to Cloud Run: `./deploy.sh <gcp-project-id> <region>` (reads backend `.env` for the env vars pushed to the service; service name `superlock-api`).

### Frontend (`frontend/`, submodule)

```bash
cd frontend
npm install
npm run dev     # localhost:3000
npm run build
npm run lint
```

### CLI (`superlock/cli`)

Plain Node (no build step) — entrypoint `bin/superlock.js`, installed as the `superlock` command.

### SDKs (`superlock/sdk/*`)

- `sdk/go`: `go test ./...` from that directory (separate module, separate go.sum).
- `sdk/node`: `npm run build` (tsc) / `npm test`.
- `sdk/python`: standard `setup.py` package (`superlock_sdk`).
- `sdk/java`: Maven (`pom.xml`).

Each SDK is versioned/published independently of the backend — check `superlock/docs/` and each SDK's own README before changing its public interface.

## Architecture (backend)

Entry point `superlock/backend/cmd/server/main.go` wires everything together and hands it to `internal/api.NewRouter`. Notable pieces:

- **`internal/api/router.go`** — single source of truth for the HTTP surface (Chi router). Routes are grouped by auth requirement and gated inline with middleware chained via `r.With(...)`, rather than checks living inside handlers:
  - `flexAuth` accepts either a Supabase JWT (dashboard/browser) or a `superlock_...` API token (SDKs/CI). `jwtAuth` is JWT-only (used for org bootstrap routes that a scoped token shouldn't be able to reach).
  - `requirePlan(db, minPlan)` (`starterGate`/`businessGate`) blocks routes below the org's plan tier (402 Payment Required).
  - `middleware.RequireScope(perm)` gates by the token's declared scope; a user JWT carries no scopes and passes every scope check — RBAC role checks still happen inside the handler.
  - A route's permission requirement is declared at registration time (e.g. `r.With(writeSecrets).Post(...)`), not buried in handler logic — when adding an endpoint, follow this pattern rather than checking permissions manually inside the handler.
- **`internal/rbac`** — role → permission matrix (`Owner`/`Admin`/`Developer`/`Reader` × `secrets:read|write|delete`, `audit:read`, `members:manage`, `billing:manage`, `tokens:manage`). Handlers additionally enforce that only Owner/Admin can read/write **protected** environments, regardless of role.
- **`internal/crypto`** — AES-256-GCM envelope encryption: each secret has its own DEK, encrypted by a master KEK (`ENCRYPTION_KEY`). Never log or serialize decrypted values.
- **`internal/store`** — one file per resource (pgx-backed), plus `migrate.go` running `migrations/*.sql` on startup.
- **`internal/ws`** — WebSocket hub for `/v1/envs/{eid}/watch`; push-invalidation messages carry `{env_id, secret_key?}`.
- **`internal/rotation`** — background worker (`worker.Run`) for scheduled secret rotation (webhook/postgres/redis backends), started from `main.go` only when Redis is configured.
- **`internal/dynamic`** — ephemeral/leased dynamic secrets; a reaper goroutine in `main.go` expires leases.
- **`internal/netguard`** — outbound SSRF guard; blocks requests to private addresses unless `SUPERLOCK_ALLOW_PRIVATE_EGRESS=true` (single-tenant opt-out, logged loudly when enabled).
- **`internal/billing`** — Razorpay integration + `IsAtLeastPlan` tier comparison. The backend's internal tier name `business` is exposed to the frontend/API consumers as `Pro` — the mapping lives at the API client boundary (see `agents.md` for details), not in the backend itself.
- **Audit log** — every mutating action is recorded HMAC-chained (`AUDIT_HMAC_KEY`); each entry's HMAC covers the previous entry's HMAC, making the chain tamper-evident.

## Working across the monorepo

- Changes to the REST API contract (routes, request/response shapes, scopes, plan gating) should be reflected in `agents.md` — it's the reference other agents/integrators read, and it will drift silently otherwise.
- Secret values must never appear in logs, error messages, or Sentry breadcrumbs — this is enforced by convention in handlers/store, not by a framework, so review new code touching `internal/crypto`, `internal/store/secret.go`, or `internal/handler/secret.go` with that in mind.
