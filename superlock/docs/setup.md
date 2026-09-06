# SuperLock — Setup Guide

## Prerequisites

- Go 1.23+
- Node.js 20+
- Docker (for local backend or Cloud Run deploy)
- A Google Cloud account (for Cloud Run)
- A Supabase account (free at supabase.com)
- An Upstash account (free at upstash.com) — optional but recommended

---

## 1. Supabase Setup

### 1.1 Create a new Supabase project

1. Go to [supabase.com](https://supabase.com) → New Project
2. Pick a name, region, and strong database password
3. Wait for the project to be provisioned (~2 min)

### 1.2 Get your credentials

From **Project Settings → API**:

- `NEXT_PUBLIC_SUPABASE_URL` → Project URL
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` → Project API Keys → `publishable`
- `SUPABASE_SECRET_KEY` → Project API Keys → `secret` (server-only, never expose to browser)

For backend JWT verification with modern Supabase projects, SuperLock uses JWKS from:
`https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json`

Legacy projects only:

- `SUPABASE_JWT_SECRET` → JWT Settings → JWT Secret (only required for HS256 tokens)

From **Project Settings → Database**:

- `DATABASE_URL` → Connection String → URI (use the **Transaction pooler** string, port 6543)

### 1.3 Enable Email Auth

Go to **Authentication → Providers → Email** — make sure it is enabled.
For dev, also enable **"Confirm email"** to be off (Authentication → Email Templates → disable confirmation) so you can test without emails.

---

## 2. Generate Encryption Keys

Run these commands locally to generate secrets:

```bash
# Generate ENCRYPTION_KEY (32-byte AES key, base64 encoded)
openssl rand -base64 32

# Generate AUDIT_HMAC_KEY
openssl rand -hex 32
```

Save these somewhere secure — they cannot be recovered. All secrets encrypted with the ENCRYPTION_KEY are unrecoverable without it.

---

## 3. Upstash Redis Setup (optional)

1. Go to [console.upstash.com](https://console.upstash.com) → Create Database
2. Choose a region close to your Cloud Run region
3. Copy the **Redis URL** (format: `rediss://default:PASSWORD@HOST.upstash.io:6379`)

If you skip Redis, rate limiting and token revocation blocklist are gracefully disabled.

---

## 4. Backend — Local Development

```bash
cd backend

# Copy and fill in your env vars
cp .env.example .env
# Edit .env with your Supabase URL, keys, encryption keys

# Install Go dependencies
go mod download

# Run migrations (they also run automatically on server start)
# The server runs migrations on startup, so just start it:
go run ./cmd/server

# Server starts at http://localhost:8080
# Health check: curl http://localhost:8080/health
```

---

## 5. Frontend — Local Development

```bash
cd frontend

# Copy and fill in your env vars
cp .env.example .env.local
# Edit .env.local:
# NEXT_PUBLIC_SUPABASE_URL=...
# NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=...
# NEXT_PUBLIC_API_URL=http://localhost:8080

# Install dependencies
npm install

# Start dev server
npm run dev

# Opens at http://localhost:3000
```

---

## 6. Backend — Deploy to Cloud Run

### 6.1 One-time Google Cloud setup

```bash
# Install gcloud CLI: https://cloud.google.com/sdk/docs/install

gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com containerregistry.googleapis.com

# Authenticate Docker
gcloud auth configure-docker
```

### 6.2 Build and deploy

```bash
cd backend

# Make the deploy script executable
chmod +x deploy.sh

# Deploy (replace with your project ID and preferred region)
./deploy.sh your-gcp-project-id us-central1
```

### 6.3 Set environment variables in Cloud Run

After the first deploy, set secrets via the console or CLI:

```bash
gcloud run services update superlock-api \
  --region us-central1 \
  --set-env-vars \
    APP_ENV=production,\
    DATABASE_URL="postgresql://...",\
    SUPABASE_URL="https://xxx.supabase.co",\
    ENCRYPTION_KEY="your-base64-32-byte-key",\
    AUDIT_HMAC_KEY="your-hmac-key",\
    REDIS_URL="rediss://...",\
    ALLOWED_ORIGINS="https://your-frontend.vercel.app",\
    SENTRY_DSN="https://..."
```

> **Tip:** For production, use Cloud Run's Secret Manager integration instead of env vars for sensitive values.

---

## 7. Frontend — Deploy to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

cd frontend
vercel

# Follow the prompts, then set env vars in Vercel dashboard:
# NEXT_PUBLIC_SUPABASE_URL
# NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
# NEXT_PUBLIC_API_URL=https://superlock-api-xxx.run.app
# NEXT_PUBLIC_SENTRY_DSN (optional)
```

Or connect your GitHub repo to Vercel for automatic deploys.

---

## 8. Sentry Setup (optional)

1. Create a project at [sentry.io](https://sentry.io)
2. Copy your DSN
3. Set `SENTRY_DSN` in backend `.env` / Cloud Run env vars
4. Set `NEXT_PUBLIC_SENTRY_DSN` in frontend `.env.local` / Vercel env vars

---

## 9. Verify Everything Works

```bash
# 1. Health check
curl https://your-cloud-run-url/health
# Expected: {"status":"ok","service":"superlock"}

# 2. Sign up at your Vercel frontend URL
# 3. Create an organization
# 4. Create a project
# 5. Add a secret
```

See `test.md` for full test steps.

---

## Environment Variable Reference

### Backend

| Variable              | Required | Description                                                               |
| --------------------- | -------- | ------------------------------------------------------------------------- |
| `DATABASE_URL`        | Yes      | Supabase Postgres connection string                                       |
| `SUPABASE_URL`        | Yes      | Your Supabase project URL                                                 |
| `SUPABASE_JWT_SECRET` | No       | Legacy HS256 token verification secret (not needed for signing keys/JWKS) |
| `ENCRYPTION_KEY`      | Yes      | Base64 32-byte AES-256 key for envelope encryption                        |
| `AUDIT_HMAC_KEY`      | Yes      | Hex key for audit log HMAC chain                                          |
| `REDIS_URL`           | No       | Upstash Redis URL (rate limiting, revocation)                             |
| `SENTRY_DSN`          | No       | Sentry error tracking DSN                                                 |
| `ALLOWED_ORIGINS`     | No       | Comma-separated CORS origins                                              |
| `PORT`                | No       | HTTP port (default: 8080)                                                 |
| `APP_ENV`             | No       | `development` or `production`                                             |

### Frontend

| Variable                               | Required | Description                        |
| -------------------------------------- | -------- | ---------------------------------- |
| `NEXT_PUBLIC_SUPABASE_URL`             | Yes      | Supabase project URL               |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Yes      | Supabase publishable API key       |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY`        | No       | Legacy fallback for older projects |
| `NEXT_PUBLIC_API_URL`                  | Yes      | Backend API URL                    |
| `NEXT_PUBLIC_SENTRY_DSN`               | No       | Sentry DSN                         |
