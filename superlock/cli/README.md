# @superlock/cli

The official Command Line Interface (CLI) for the **SuperLock** Zero-Trust Secrets & Configuration Platform.

---

## 📦 Installation

Install globally via npm:

```bash
npm install -g @superlock/cli
```

Or run directly via `npx`:

```bash
npx @superlock/cli --help
```

---

## 🚀 Quick Start

### 1. Authenticate

```bash
superlock auth login
```

Opens your browser to verify your identity and establishes a cryptographic session on your local machine.

### 2. Link Project, Environment & Local `.env`

Navigate to your application repository and bind it to a SuperLock environment:

```bash
superlock link
```

An interactive walkthrough: pick a project (or create one), pick an environment (or create one), pick the local env file it maps to, then optionally **push** those local variables into the vault or **pull** the vault's secrets down into the file. The binding lands in `.superlockrc` — IDs only, never values — and later commands in that directory default to the bound environment.

Every step has a flag, so CI never has to answer a prompt:

```bash
superlock link -p <projectId> -e production -f .env --no-sync
```

### 3. Run Process with Injected Secrets

Inject decrypted secrets directly into your development or build process without writing plaintext `.env` files:

```bash
superlock run -- npm run dev
```

---

## 🛠️ Commands

| Command | Description |
|---|---|
| `superlock auth login` | Authenticate CLI via SSO / Web dashboard |
| `superlock link` | Bind the working directory and a local env file to a remote environment, with optional push/pull sync |
| `superlock run -- <cmd>` | Inject runtime secrets directly into process execution |
| `superlock pull` | Export environment secrets securely to local `.env.superlock` |
| `superlock secret set <key> <val>` | Write or update a secret in the linked environment |
| `superlock rotate <key>` | Trigger immediate zero-downtime rotation cycle for a secret |
| `superlock verify-audit` | Verify HMAC chain integrity on the tamper-evident audit ledger |

---

## 📄 License

MIT © SuperLock
