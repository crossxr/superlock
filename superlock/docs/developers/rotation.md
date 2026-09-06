# Secret rotation

`internal/rotation` replaces a secret's value on a schedule, or on demand.

## Shape

```
Worker.Run          ticks every 60s
  └─ tick           store.ListDueRotations (enabled, next_rotation_at <= now, limit 50)
       └─ rotate    one goroutine per due schedule
            ├─ Redis SET NX lock, keyed by secret ID   -- one instance only
            ├─ write rotation_history row (pending)
            ├─ load the secret                          -- for its key and env
            ├─ callBackend -> new value
            ├─ encrypt, RotateSecretValue               -- bumps version
            ├─ UpdateRotationAfterSuccess               -- schedules the next run
            ├─ write rotation_history row (success)
            └─ hub.Broadcast                            -- invalidate SDK caches
```

`TriggerManual` skips the schedule check and calls `rotate` directly. It still
takes the lock, so a manual trigger during a scheduled run is a no-op rather
than a double rotation.

The lock has a 30-second TTL while a webhook may take up to 15 seconds plus
retries. It is a de-duplication measure, not a correctness guarantee — do not
extend it into one without also handling the case where the lock expires
mid-rotation.

## Backends

| Backend | Status |
|---|---|
| `webhook` | Implemented. |
| `postgres` | Implemented — `ALTER ROLE ... WITH PASSWORD`. |
| `redis` | **Constant exists, `callBackend` has no case for it.** Selecting it fails with "unsupported backend". |
| `mysql` | Not a rotation backend at all. `internal/dynamic` has a MySQL path, but `execMySQL` is a stub that returns an error. |

The user-facing docs previously claimed native MySQL and Redis rotation. They
did not exist. If you implement one, update `frontend/app/docs/content/rotation.md`
in the same change.

## The webhook contract

### What it used to be, and why it was a hole

The old payload was:

```json
{ "secret_id": "...", "old_value": "<the decrypted secret>" }
```

sent with `http.DefaultClient` to whatever URL the config named — no allowlist,
no timeout, no redirect limit, no signature.

Combined with the missing ownership check on `POST /secrets/{sid}/rotation`
(fixed alongside), that was remote secret theft in three calls: attach a
schedule to a victim's secret, point it at your own host, trigger it, receive
the plaintext. The webhook did not need to do anything but log the request body.

### What it is now

The payload identifies the secret and carries nothing sensitive:

```json
{
  "version": "2026-09-06",
  "rotation_id": "9f1c...",
  "secret_id": "3ab8...",
  "key": "STRIPE_KEY",
  "env_id": "71dd...",
  "nonce": "kQ7v...",
  "requested_at": "2026-09-06T13:41:02Z"
}
```

A receiver that genuinely needs the outgoing value reads it through the API with
its own token. That keeps the value inside an authenticated, audited, rate-
limited path instead of being pushed to whatever URL a config happens to name.
`version` is there so a future change is detectable. Bump it and document the
change; do not silently reshape the body.

The request:

- goes through `netguard` — see [egress-security.md](egress-security.md)
- carries `X-SuperLock-Signature` when the schedule has a signing secret
- times out after 15s
- does not follow redirects
- reads at most 64 KiB of response

Caller-supplied headers are applied *before* ours, so a config cannot override
`Content-Type` or forge the signature header. `TestWebhookCallerHeadersCannotOverrideSignature`
pins that ordering — if you refactor the header block, keep it.

### Signing

```http
X-SuperLock-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>
```

The MAC covers `"<t>." + rawBody`. The timestamp is inside the signed material,
so a receiver can reject replays by refusing signatures outside its tolerance
window — without that, a captured request replays forever.

The signing secret is generated in `CreateRotationSchedule`, stored in
`config_json`, and returned **once** in the create response. Every subsequent
read redacts it, so a lost secret means recreating the schedule. That is
deliberate: a signing secret retrievable over the API is barely a secret.

`SignWebhook` is exported so tests — and eventually a CLI verify command — build
the header exactly the way the worker does. Keep it that way; a second
implementation will drift.

## config_json holds credentials

For `postgres` the blob contains an admin DSN. For `webhook` it contains the
signing secret and any custom headers, which are frequently bearer tokens.

Two consequences:

1. `RotationSchedule.ConfigJSON` is `json:"-"`. Responses go through
   `rotationView`, which calls `safeConfig` to build an explicit allowlist of
   non-credential fields. **Adding a field to a config means revisiting
   `safeConfig`** — it allowlists, so a new field is hidden by default, which is
   the right failure direction.
2. It is stored in plaintext in Postgres. That is a real gap in a product whose
   entire proposition is not doing that, and it is on the Phase 1 list: encrypt
   `config_json` with the same envelope scheme as secret values.

## Failure handling

A failed rotation writes a `failed` history row, reports to Sentry, and emails
the org owners. The secret keeps its old value — there is no partial state,
because the value is only written after the backend returns successfully.

There is no retry and no backoff. A schedule that fails is simply retried at its
next interval, which for a 30-day schedule means a month. Worth revisiting.

Error text from the backend is stored in `rotation_history.error_msg` and
returned by the history endpoint. Backend errors can quote connection strings
and remote response bodies, so treat that column as sensitive; the endpoint is
ownership-checked, but it should not be widened without sanitising first.

## Tests

`worker_test.go` builds a `Worker` with only a guard — `callWebhook` touches no
store — and points it at an `httptest` server. The important one is
`TestWebhookPayloadOmitsSecretValue`: it asserts the body contains neither the
value nor an `old_value` key at all. That test is the regression guard for the
original vulnerability; do not weaken it to "contains the expected fields".
