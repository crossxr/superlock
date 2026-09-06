# SuperLock — LLM Agent Context

> This document provides up-to-date context for AI coding assistants, LLM agents, and copilots working on or integrating with the SuperLock platform. Include this file in your project root or reference it in your agent configuration.

## What is SuperLock?

SuperLock is a **secrets management platform** for engineering teams. It stores, encrypts, and delivers application secrets (API keys, database passwords, tokens, sensitive config) to apps and pipelines. Every secret is encrypted with **AES-256-GCM** using a per-secret data encryption key (DEK) — secrets are never stored in plaintext.

**Product URL:** https://superlock.superxepic.dev  
**API Base URL:** `https://superlock-api.superxepic.dev`  
**WebSocket URL:** `wss://superlock-api.superxepic.dev/v1/envs/{eid}/watch`

---

## Architecture

### Data Model Hierarchy

```text
Organization (top-level workspace)
├── Members (users with RBAC roles)
├── API Tokens (scoped, long-lived credentials)
├── Projects (logical service groupings)
│   └── Environments (dev / staging / production / custom)
│       ├── Secrets (encrypted key-value pairs)
│       │   ├── Versions (immutable history, Starter+)
│       │   └── Rotation schedules (webhook / postgres / redis, Starter+)
│       └── Dynamic Secret configs (ephemeral credentials, Pro+)
├── Audit Log (HMAC-chained, tamper-evident)
├── Approvals (2-person workflow for protected envs, Pro+)
└── Billing (Razorpay subscriptions)
```

### Authentication

Two auth methods exist:

1. **User JWT** — Short-lived, produced by Supabase Auth. Used by the dashboard and CLI. Sent as `Authorization: Bearer <jwt>`.
2. **API Token** — Long-lived, scoped credential for SDKs, CI/CD, and server-to-server. Created in dashboard under Settings → Tokens. Scopes: `secrets:read`, `secrets:write`, `secrets:delete`, `audit:read`, `tokens:manage`. Prefixed with `superlock_`.

### RBAC Roles

| Role | Read Secrets | Write Secrets | Delete Secrets | Manage Members | Billing |
|------|:---:|:---:|:---:|:---:|:---:|
| **Owner** | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Admin** | ✓ | ✓ | ✓ | ✓ | — |
| **Developer** | ✓ | ✓ (non-protected) | — | — | — |
| **Reader** | ✓ (non-protected) | — | — | — | — |

**Protected environments** (e.g., production): Only Owner and Admin can read/write, regardless of role.

---

## Plan Tiers & Limits

| Feature | Free | Starter ($29/seat/mo) | Pro ($79/seat/mo) | Enterprise (Custom) |
|---|:---:|:---:|:---:|:---:|
| Max secrets | 50 | Unlimited | Unlimited | Unlimited |
| Max projects | 1 | 5 | Unlimited | Unlimited |
| Envs per project | 2 | 5 | Unlimited | Unlimited |
| Team seats | 1 | 10 | 100 | Unlimited |
| API tokens | 3 | 10 | Unlimited | Unlimited |
| Audit retention | 7d | 90d | 365d | 10 years |
| Secret versioning | — | ✓ | ✓ | ✓ |
| Secret rotation | — | ✓ | ✓ | ✓ |
| Secret sharing | — | ✓ | ✓ | ✓ |
| WebSocket live updates | — | ✓ | ✓ | ✓ |
| Dynamic secrets | — | — | ✓ | ✓ |
| CI/CD integrations | — | — | ✓ | ✓ |
| Approval workflows | — | — | ✓ | ✓ |
| Analytics | — | — | ✓ | ✓ |

> **Note:** The backend uses `business` as the internal tier name for what the frontend displays as `Pro`. The API client maps between them.

---

## REST API Reference

**Base URL:** `https://superlock-api.superxepic.dev/v1`

All endpoints require `Authorization: Bearer <token>` unless noted. Responses are JSON. Timestamps are ISO 8601 UTC.

### Core Endpoints (All Plans)

| Method | Path | Description |
|---|---|---|
| `GET` | `/projects` | List all projects |
| `POST` | `/projects` | Create project `{ name, description }` |
| `GET` | `/projects/{pid}` | Get project |
| `DELETE` | `/projects/{pid}` | Delete project + all envs/secrets |
| `GET` | `/projects/{pid}/envs` | List environments |
| `POST` | `/projects/{pid}/envs` | Create environment `{ name, is_protected }` |
| `GET` | `/projects/{pid}/envs/{eid}/secrets` | List secrets (metadata only, no values) |
| `POST` | `/projects/{pid}/envs/{eid}/secrets` | Create secret `{ key, value }` |
| `GET` | `/secrets/{sid}` | Get secret with decrypted value |
| `PUT` | `/secrets/{sid}` | Update secret `{ value }` |
| `DELETE` | `/secrets/{sid}` | Delete secret + all versions |
| `GET` | `/orgs/me/audit` | List audit events `?limit=&offset=&action=` |
| `GET` | `/tokens` | List API tokens |
| `POST` | `/tokens` | Create token `{ name, scopes, expires_at? }` |
| `DELETE` | `/tokens/{tid}` | Revoke token |

### SDK Endpoint (API Token Only)

| Method | Path | Description |
|---|---|---|
| `GET` | `/envs/{eid}/secrets/values` | Bulk pull — all decrypted secrets as `{ KEY: value }` map |

### Starter+ Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/secrets/{sid}/versions` | List secret version history |
| `POST` | `/secrets/{sid}/rotation` | Create rotation schedule |
| `GET` | `/secrets/{sid}/rotation` | Get rotation schedule |
| `POST` | `/secrets/{sid}/rotate` | Trigger immediate rotation |
| `DELETE` | `/rotation/{schedid}` | Delete rotation schedule |
| `POST` | `/share` | Create share link |
| `GET` | `/share` | List share links |
| `GET` | `/share/{shareId}` | Access share (public, no auth) |
| `DELETE` | `/share/{shareId}` | Delete share link |

### Pro+ Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/approvals` | List pending approvals |
| `POST` | `/approvals/{aid}/resolve` | Approve/reject `{ action }` |
| `POST` | `/projects/{pid}/envs/{eid}/dynamic` | Create dynamic config |
| `GET` | `/projects/{pid}/envs/{eid}/dynamic` | List dynamic configs |
| `POST` | `/dynamic/{cfgid}/generate` | Generate ephemeral credential (lease) |
| `POST` | `/dynamic/leases/{lid}/revoke` | Revoke lease |
| `GET` | `/orgs/me/dynamic/leases` | List all leases |
| `DELETE` | `/dynamic/{cfgid}` | Delete dynamic config |
| `GET` | `/orgs/me/analytics/heatmap` | Secret access heatmap |
| `GET` | `/orgs/me/analytics/unused` | Unused secrets report |
| `GET` | `/projects/{pid}/envs/{eid}/cicd-snippet` | CI/CD snippet `?provider=` |

### Billing Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/billing/subscribe` | Create subscription `{ plan_tier }` |
| `POST` | `/billing/cancel` | Cancel subscription |
| `GET` | `/billing/status` | Subscription status + usage |
| `POST` | `/webhooks/razorpay` | Razorpay webhook (signature-verified, no auth) |

---

## SDKs

### Go SDK

**Install:** `go get github.com/superlock/sdk-go`

```go
import "github.com/superlock/sdk-go"

client, err := superlock.New(
    superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
    superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
)
if err != nil { log.Fatal(err) }
defer client.Close()

val, ok := client.Get("DATABASE_URL")       // (string, bool)
val = client.MustGet("DATABASE_URL")         // panics if missing
val = client.GetOrDefault("HOST", "localhost") // with default
all := client.GetAll()                        // map[string]string
client.Refresh(ctx)                           // force refresh
```

**Options:** `WithBaseURL`, `WithTTL`, `WithPollInterval`, `WithTimeout`, `WithMaxRetries`, `WithHTTPClient`, `WithLogger`, `WithOnRefresh`, `WithOnError`.

### Node.js SDK

**Install:** `npm install @superlock/node`

```typescript
import { SuperLockClient } from '@superlock/node';

const client = new SuperLockClient({
  token: process.env.SUPERLOCK_TOKEN!,
  env: process.env.SUPERLOCK_ENV_ID!,
});

await client.ready();
const dbUrl = await client.get('DATABASE_URL');   // string | null
const all = await client.getAll();                 // Record<string, string>
await client.refresh();                            // force refresh
client.destroy();                                  // cleanup
```

**Events:** `refresh`, `invalidation`, `error`.  
**Options:** `baseURL`, `ttl`, `cacheSize`, `pollInterval`, `timeout`, `maxRetries`, `fetch`.  
**Next.js:** Works in API routes, `getServerSideProps`, middleware, and server components. **Server-side only — never expose the token to the client bundle.**

### Python SDK

**Install:** `pip install superlock-sdk`

```python
from superlock_sdk import SuperLockClient

client = SuperLockClient(
    token=os.environ["SUPERLOCK_TOKEN"],
    env=os.environ["SUPERLOCK_ENV_ID"],
)

db_url = client.get("DATABASE_URL")
all_secrets = client.get_all()
client.close()
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, React 19, TypeScript, Vanilla CSS |
| Backend | Go 1.23, Chi router, PostgreSQL (pgx), Redis |
| Auth | Supabase Auth (JWT) + custom API tokens (SHA-256 hashed) |
| Encryption | AES-256-GCM, per-secret DEK, master key envelope |
| Billing | Razorpay subscriptions + webhooks |
| Monitoring | Sentry (frontend + backend) |
| WebSocket | Gorilla WebSocket, hub-based pub/sub per environment |
| Audit | HMAC-SHA256 chained, append-only, tamper-evident |

---

## Environment Variables

### Backend

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `JWT_SECRET` | Supabase JWT verification secret |
| `SUPABASE_URL` | Supabase project URL |
| `ENCRYPTION_KEY` | 32-byte hex master encryption key |
| `AUDIT_HMAC_KEY` | HMAC key for audit chain |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins |
| `RAZORPAY_KEY_ID` | Razorpay key ID |
| `RAZORPAY_KEY_SECRET` | Razorpay key secret |
| `RAZORPAY_WEBHOOK_SECRET` | Razorpay webhook signature secret |
| `RZP_PLAN_STARTER` | Razorpay plan ID for Starter |
| `RZP_PLAN_BUSINESS` | Razorpay plan ID for Pro/Business |
| `SENTRY_DSN` | Sentry DSN for error tracking |
| `RESEND_API_KEY` | Resend email API key |

### Frontend

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_URL` | Backend API URL |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anonymous key |
| `NEXT_PUBLIC_RAZORPAY_KEY_ID` | Razorpay public key |
| `NEXT_PUBLIC_SENTRY_DSN` | Sentry DSN |

---

## Common Patterns for Agents

### Creating a new secret programmatically

```bash
curl -X POST https://superlock-api.superxepic.dev/v1/projects/{pid}/envs/{eid}/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "MY_SECRET", "value": "s3cr3t_value"}'
```

### Fetching all secrets for an environment (SDK flow)

```bash
curl https://superlock-api.superxepic.dev/v1/envs/{eid}/secrets/values \
  -H "Authorization: Bearer $SUPERLOCK_TOKEN"
# Returns: { "KEY1": "value1", "KEY2": "value2", ... }
```

### Secret reference syntax

Secrets can reference other secrets: `${secret:OTHER_KEY}`. Resolved at read time, up to 5 levels deep.

```text
DATABASE_URL = postgresql://${secret:DB_USER}:${secret:DB_PASS}@${secret:DB_HOST}/mydb
```

---

## Important Notes for Code Generation

1. **Backend tier names:** The backend uses `business` internally. The frontend displays it as `Pro`. The API client (`lib/api.ts`) maps `business ↔ pro` at the network boundary.
2. **Auth flow:** Dashboard uses Supabase JWT. SDKs and CI/CD use API tokens. The `FlexAuthMiddleware` in the backend accepts both.
3. **RBAC is enforced server-side.** Frontend gating is cosmetic — always validate roles on the backend.
4. **Encryption is envelope-based.** Each secret has its own DEK encrypted by the master key. Never log or serialize decrypted values.
5. **Audit entries are HMAC-chained.** Each entry's HMAC includes the previous entry's HMAC. Breaking the chain is detectable with `superlock verify-audit`.
6. **WebSocket messages** contain `{ env_id, secret_key? }` — the SDK invalidates the specific cache entry and triggers a refresh.
7. **Secret keys are always uppercased** server-side. SDKs normalize to uppercase on `Get()`.
