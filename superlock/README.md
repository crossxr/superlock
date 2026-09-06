# SuperLock — Secrets & Config Manager

> Secure, simple secrets management for engineering teams. No Vault cluster, no per-API-call pricing.

**Core Platform** | Go 1.23 + Chi + Next.js 15 + Supabase + Cloud Run

---

## Quick Start

```text
superlock/
├── backend/      # Go API server (Cloud Run)
├── cli/          # SuperLock CLI (Node.js)
├── sdk/          # Official SDKs (Go, Node, Python, Java)
├── docs/         # Setup, test, and developer architecture docs
└── CHANGELOG.md
```

See **[docs/setup.md](docs/setup.md)** for full setup instructions.

## Phase 1 Features

- AES-256-GCM envelope encryption (per-secret DEK)
- Secret CRUD with versioning
- Environment scoping (dev / staging / prod / custom)
- Immutable audit log with HMAC chain
- RBAC (Owner / Admin / Developer / Reader)
- API token management with scopes
- Supabase Auth (email + password)
- Deployed on Google Cloud Run + Vercel

## Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.23, Chi v5 |
| Auth | Supabase Auth (JWT) |
| Database | Supabase Postgres (pgx v5) |
| Cache | Upstash Redis |
| Encryption | AES-256-GCM (stdlib) |
| Frontend | Next.js 15, React 19, Tailwind CSS |
| Hosting | Google Cloud Run + Vercel |
| Errors | Sentry (backend + frontend) |
