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

### 2. Link Project & Environment

Navigate to your application repository and link it to a SuperLock project boundary:

```bash
superlock link
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
| `superlock link` | Link local working directory to a SuperLock remote project |
| `superlock run -- <cmd>` | Inject runtime secrets directly into process execution |
| `superlock pull` | Export environment secrets securely to local `.env.superlock` |
| `superlock secret set <key> <val>` | Write or update a secret in the linked environment |
| `superlock rotate <key>` | Trigger immediate zero-downtime rotation cycle for a secret |
| `superlock verify-audit` | Verify HMAC chain integrity on the tamper-evident audit ledger |

---

## 📄 License

MIT © SuperLock
