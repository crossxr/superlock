# Changelog

All notable changes to Nano are documented here.

---

## [0.1.0] — Phase 1 — Foundation

**Release date:** March 2026  
**Status:** Initial release

### Added

#### Backend (Go 1.23)

- **Project structure** — monorepo with `backend/` and `frontend/` packages
- **Go API server** — Chi v5 router, graceful shutdown, 30s request timeout
- **Sentry integration** — error tracking and performance tracing on all routes
- **CORS middleware** — configurable allowed origins via `ALLOWED_ORIGINS` env var
- **Supabase Auth middleware** — JWT RS256 verification against Supabase JWT secret
- **API token middleware** — `nano_` prefixed tokens, SHA-256 hashed, scope-checked
- **Envelope encryption engine** — AES-256-GCM per-secret DEK, KEK from env var (Cloud KMS in Phase 2)
- **RBAC system** — four roles: Owner, Admin, Developer, Reader with permission matrix
- **Organization management** — create org, get org, assign owner role on first login
- **User management** — auto-provision users on first Supabase login, upsert pattern
- **Project CRUD** — create, list, get, soft-delete projects with slug generation
- **Environment CRUD** — create environments with protected flag, auto-create dev/staging/prod on project creation
- **Secret CRUD** — create, read, update, soft-delete secrets with envelope encryption
- **Secret versioning** — previous version saved to `secret_versions` on every update
- **Bulk secret pull** — `GET /v1/envs/:eid/secrets/values` — all decrypted secrets in one call (SDK optimized)
- **Audit log** — append-only `audit_events` table with HMAC chain for tamper detection
- **API token management** — create scoped tokens, list, revoke (Redis blocklist + DB revoked_at)
- **Redis cache** — env etag invalidation on secret writes, token revocation blocklist, rate limiting hooks
- **Database migrations** — golang-migrate with up/down SQL files, auto-run on server start
- **Docker** — multi-stage Dockerfile with scratch runtime image (~8MB)
- **Cloud Run deploy script** — `deploy.sh` for one-command GCR build + Cloud Run deploy

#### Frontend (Next.js 15 + React 19)

- **Supabase Auth** — email/password sign up and sign in, session management via SSR cookies
- **Auth middleware** — Next.js middleware guards all dashboard routes, redirects to login
- **Dark theme UI** — custom Tailwind dark design system (`gray-950` base, indigo accent)
- **Responsive sidebar** — collapsible on mobile with overlay, persistent on desktop
- **Onboarding flow** — create organization page shown on first login
- **Dashboard overview** — stats cards, recent projects list, recent audit activity feed
- **Projects page** — list, create, delete projects with inline form
- **Project detail page** — environment cards with color coding and protected indicator
- **Secrets page** — list secrets (keys only), inline reveal/hide values, edit, delete, search
- **Secret row component** — reveal value on demand, inline edit with textarea, copy to clipboard, version/expiry metadata
- **Audit log page** — paginated table with action filter, color-coded action badges
- **API tokens page** — create tokens with scopes, one-time reveal banner, revoke tokens
- **Members page** — list org members with roles (invite flow in Phase 2)
- **Sentry** — client-side error tracking via `@sentry/nextjs`

#### Infrastructure & Docs

- `docs/setup.md` — full setup guide for Supabase, Cloud Run, Vercel, Upstash
- `docs/test.md` — 17-step manual test plan covering all Phase 1 features
- `backend/.env.example` — all backend environment variables documented
- `frontend/.env.example` — all frontend environment variables documented
- `backend/migrations/001_initial_schema.up.sql` — full Postgres schema
- `backend/migrations/001_initial_schema.down.sql` — rollback migration

### Architecture Decisions

- **KEK from env var (Phase 1):** Cloud KMS integration deferred to Phase 2 to ship faster. The encryption engine interface is already abstracted (`internal/kms` package) to make the upgrade seamless.
- **Supabase for Auth + DB:** Eliminates the need to self-host Postgres and manage auth. Supabase's JWT is verified in Go middleware — no SDK dependency in the backend.
- **Upstash Redis (optional):** Rate limiting and token blocklisting gracefully degrade if Redis is unavailable. This means the server works with zero Redis dependency for local development.
- **Single binary:** The Go server compiles to a scratch Docker image (~8MB). Cloud Run cold starts in <500ms.
- **No microservices:** Everything in one process with internal packages. Rotation worker is a separate binary but shares the same codebase.

### Known Limitations (to be addressed in Phase 2)

- Member invitations not yet implemented
- Rotation engine not yet built
- WebSocket invalidation feed not yet built
- Node.js and Python SDKs not yet built
- Stripe billing not yet integrated
- Rate limiting middleware defined but not wired to routes (Redis required)
- Protected environment 2-person approval not yet implemented

---

*Phase 2 planned features: Stripe billing, rotation engine (webhook + Postgres), WebSocket invalidation, Node.js/Python SDKs, CLI tool, email invites, 2-person approval for prod writes.*
