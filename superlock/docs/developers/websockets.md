# WebSocket invalidation stream (`internal/ws`)

A per-environment fan-out that tells connected SDKs when a secret changed, so
they can drop a cache entry instead of polling.

```
GET /v1/envs/{eid}/watch      API token auth -> RequireOrg -> Starter gate -> WatchEnvironment
```

Messages are one-way, server to client:

```json
{ "type": "secret.rotated", "env_id": "71dd...", "secret_key": "STRIPE_KEY" }
```

`type` is one of `secret.updated`, `secret.deleted`, `secret.rotated`. The
payload deliberately carries the key name, never the value — a client that
receives one refetches through the authenticated API.

## Authorization

`Hub.ServeWS` performs **no** authorization. It documents this, and it is the
caller's job. `handler.WatchEnvironment` does the work:

1. parse the env ID
2. `verifyEnvAccess` — environment → project → org
3. `rbac.CanReadSecret(role, env.IsProtected)`
4. only then upgrade

The route previously passed the URL parameter straight into `ServeWS` from an
inline closure in the router, with no check at all. Any valid API token could
subscribe to any organization's environment and watch its secret key names and
change events stream by. Key names alone are a meaningful leak — they enumerate
a competitor's infrastructure — and the events disclose deploy timing.

Keep authorization in the handler rather than the hub. The hub is a fan-out
primitive; giving it opinions about orgs would put the check somewhere nobody
looks when adding a second entry point.

## Origin checking

`CheckOrigin` used to return `true` unconditionally, which disables the browser
same-origin protection that the WebSocket handshake exists to provide.

The current rule:

- **No `Origin` header** → allow. SDKs, the CLI and server processes do not send
  one. The API token is the authentication.
- **`Origin` present** → must match `ALLOWED_ORIGINS` exactly (case-insensitive),
  or be `*`.

A browser cannot forge `Origin`, so matching it is what stops a hostile page
from opening a socket with a token it obtained some other way. A non-browser
client can trivially omit or fake the header — which is why the header is not
doing the authentication, the token is.

`NewHub` takes the origin list. Pass the same value the CORS layer uses; they
should never disagree.

## Concurrency rules

The hub is shared mutable state touched from HTTP handlers and from the rotation
worker. Two rules, both learned the hard way:

### Hold the read lock across the entire broadcast

```go
h.mu.RLock()
defer h.mu.RUnlock()
for c := range h.clients[envID] {
    select {
    case c.send <- b:
    default:
    }
}
```

The earlier version took the lock, copied the map reference, released, and *then*
iterated and sent. `unregister` holds the write lock while it both deletes from
that map and closes the client's channel, which left two races:

- iterating the live map while it is written — `fatal error: concurrent map
  iteration and map write`
- sending on a channel closed in between — `panic: send on closed channel`

Both kill the process. `Broadcast` is called from the rotation worker goroutine,
not an HTTP handler, so chi's `Recoverer` never sees it: one client
disconnecting during a rotation broadcast took the server down.

Holding the lock for the loop is cheap because **every send is non-blocking**.
If you ever remove the `default:` case, this becomes a deadlock — a slow client
would hold the read lock and block every registration. Do not remove it.

### The write pump owns the connection

`unregister` closes `send`. The write pump sees the closed channel, sends a
close frame and calls `conn.Close()`. Nothing else closes the connection.

## Liveness

Read and write deadlines, a ping every 54s, and a 60s pong window. A peer that
disappears without a FIN — a laptop lid, a dropped NAT entry — used to leave the
read pump blocked on `ReadMessage` forever, holding a goroutine, a connection
and a slot in the client map for the process lifetime. `SetReadLimit` caps what
a client can send; clients are not expected to send anything.

`pingPeriod` must stay below `pongWait` or a live peer gets reaped for not
answering a ping we never sent.

## Delivery guarantees

There are none. A client with a full 64-message buffer has events dropped
silently, and a client that reconnects misses everything sent while it was away.

This is acceptable because the events are cache *invalidations*: the SDK also
has a TTL, so a missed event costs staleness until the TTL expires, not
correctness. Do not build anything that needs exactly-once delivery on top of
this without adding a resync-on-connect step first.

## Tests

`hub_test.go` covers origin matching — including the lookalike-domain cases,
which a naive `strings.Contains` would let through — and drives concurrent
`Broadcast`/`register`/`unregister` to reproduce the crash.

The race detector needs cgo and a 64-bit gcc, which is not available on every
dev box. Both failure modes are hard runtime aborts, so the test catches them
without `-race`; run `go test -race ./...` in CI anyway.

To confirm the concurrency test is real, revert `Broadcast` to release the lock
before iterating and watch it die.
