# SuperLock — Zero-Trust Secrets & Config Orchestration Platform

<p align="center">
  <strong>High-performance, zero-trust secrets management and dynamic configuration platform for modern engineering teams.</strong>
</p>

---

## 🌟 Overview

**SuperLock** is a developer-centric secrets manager and configuration delivery platform built for speed, security, and simplicity. It replaces bulky HashiCorp Vault deployments and opaque cloud secrets managers with an end-to-end encrypted, versioned, and auditable platform.

- 🔐 **AES-256-GCM Envelope Encryption**: Per-secret Data Encryption Keys (DEKs) encrypted by a master Key Encryption Key (KEK). Decrypted in memory, never stored in plaintext.
- 🔄 **Automated Secret Rotation**: Zero-downtime automated rotation with signed webhook callbacks (`X-SuperLock-Signature`) and built-in database/cache rotation.
- ⚡ **Real-Time Synchronisation**: Low-latency WebSocket streaming (`/v1/envs/{eid}/watch`) with push invalidation and automatic reconnection.
- 🛡️ **Zero-Trust Access Control**: Granular RBAC, scoped API tokens (`superlock_...`), and dual-custody approval workflows for protected environments.
- 📜 **Tamper-Evident Audit Logging**: Cryptographically verified HMAC-SHA256 chained audit trail.
- ⏳ **Ephemeral Dynamic Secrets**: On-demand lease generation with automatic TTL expiration.

---

## 📁 Repository Structure

This monorepo houses the complete SuperLock ecosystem:

```text
.
├── superlock/
│   ├── backend/        # Go 1.23+ REST & WebSocket API (Chi, pgx, Redis, Sentry)
│   ├── cli/            # SuperLock CLI tool (Node.js / npm i -g superlock)
│   ├── sdk/            # Multi-language client SDKs
│   │   ├── go/         # Go SDK (github.com/superlock/sdk-go)
│   │   ├── node/       # Node.js / TypeScript SDK (@superlock/node)
│   │   ├── python/     # Python SDK (superlock-sdk)
│   │   └── java/       # Java SDK (dev.superlock:superlock-sdk)
│   └── docs/           # Architecture, security & setup documentation
├── frontend/           # Next.js 15 web dashboard & documentation portal (Submodule)
├── agents.md           # LLM agent & copilot integration context
└── README.md
```

---

## 🚀 Quick Start

### 1. SuperLock CLI

Install globally via npm:

```bash
npm install -g superlock
```

Log in and inject secrets directly into your development processes:

```bash
# Authenticate
superlock login

# Link your project & environment
superlock link

# Run your application with injected secrets
superlock run -- npm run dev
```

---

### 2. Multi-Language SDKs

#### Go

```bash
go get github.com/superlock/sdk-go
```

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/superlock/sdk-go"
)

func main() {
    client, err := superlock.New(
        superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
        superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    dbURL, _ := client.Get("DATABASE_URL")
    fmt.Println("Connected DB:", dbURL)
}
```

#### Node.js / TypeScript

```bash
npm install @superlock/node
```

```typescript
import { SuperLockClient } from '@superlock/node';

const client = new SuperLockClient({
  token: process.env.SUPERLOCK_TOKEN!,
  env: process.env.SUPERLOCK_ENV_ID!,
});

await client.ready();
const dbUrl = await client.get('DATABASE_URL');
console.log('Database URL:', dbUrl);
```

#### Python

```bash
pip install superlock-sdk
```

```python
import os
from superlock_sdk import SuperLockClient

client = SuperLockClient(
    token=os.environ["SUPERLOCK_TOKEN"],
    env=os.environ["SUPERLOCK_ENV_ID"],
)

db_url = client.get("DATABASE_URL")
print("Database URL:", db_url)
client.close()
```

---

### 3. Backend API Server

Requirements: Go 1.23+, PostgreSQL, Redis.

```bash
cd superlock/backend

# Copy and configure environment variables
cp .env.example .env

# Run local development server
go run ./cmd/server
```

### 4. Web Dashboard & Documentation

Requirements: Node.js 20+.

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the SuperLock dashboard.

---

## 🔒 Security & Architecture

For detailed deep-dives into our security model:

- [Setup Guide](superlock/docs/setup.md)
- [Testing & Verification Guide](superlock/docs/test.md)
- [Webhook Secret Rotation Architecture](superlock/docs/developers/rotation.md)
- [Outbound Egress & SSRF Protection](superlock/docs/developers/egress-security.md)
- [WebSocket Live Sync Architecture](superlock/docs/developers/websockets.md)

---

## 📄 License

Proprietary. All rights reserved. © SuperLock.
