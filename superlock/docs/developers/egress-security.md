# Egress security (`internal/netguard`)

Every outbound request to a destination the customer chose goes through this
package. Rotation webhooks and dynamic-secret DSNs both take a URL or host from
a config blob and have the server connect to it.

## Why it exists

Without a guard, "the customer picks the address and our server makes the
request" is a server-side request forgery primitive. The caller supplies the
target, we supply the network position — inside the VPC, past the firewall,
holding an instance role — and the response body or the error text is the
oracle that reads the result back.

The concrete targets on a typical cloud host:

- `169.254.169.254` — instance metadata. On IMDSv1 this is credentials.
- `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12` — internal services that
  assume network position *is* authentication.
- `127.0.0.1` — our own admin surfaces, Redis, anything bound to loopback.

## Why the check is at dial time

The obvious implementation resolves the hostname, checks the addresses, then
makes the request. That has a window: the attacker controls the DNS, so the
name resolves to a public address for the check and a private one for the
connection. The check passes and the socket still lands on `169.254.169.254`.
Short TTLs make this reliable, not theoretical.

`netguard` instead hooks `net.Dialer.Control`, which runs after resolution and
immediately before `connect(2)`, with the concrete address the socket is about
to use:

```go
Control: func(network, address string, _ syscall.RawConn) error {
    host, _, _ := net.SplitHostPort(address)
    addr, err := netip.ParseAddr(host)
    if err != nil {
        return fmt.Errorf("%w: unparseable ip %q", ErrBlockedAddress, host)
    }
    return g.CheckAddr(addr)
},
```

There is no window left: whatever the name resolved to, *this* is the address
being connected to, and it is checked. The hook fires again for every new
connection, so a redirect or a retry cannot slip past either.

## What is blocked

`blockedPrefixes` in `netguard.go` is the list. It covers loopback, RFC1918,
CGNAT, link-local (which is where cloud metadata lives), the unspecified and
broadcast addresses, the IETF test and benchmark ranges, and the IPv6
equivalents.

Two details worth keeping:

- **IPv4-mapped IPv6.** `::ffff:169.254.169.254` is the metadata endpoint
  written as an IPv6 address. `CheckAddr` calls `Unmap()` first so it is
  compared against the IPv4 ranges. Without that line the whole blocklist is
  bypassable with a different notation.
- **Multicast and interface-local** are rejected via `netip` predicates rather
  than prefixes, because there are several ranges and the predicates are
  already correct.

## Redirects

Not followed. `CheckRedirect` returns `ErrRedirect`.

Following them would mean re-checking each hop, and the `Control` hook does
handle that correctly — but a rotation receiver has no legitimate reason to
redirect, and every hop is another chance for a mistake. Refusing is the smaller
surface.

## Usage

```go
guard := netguard.New(allowPrivate)

// Validate a URL when it is first configured, so the customer gets an error
// at config time instead of a silent failure at 3am.
u, err := guard.ParseURL(cfg.URL)

// Make the request.
resp, err := guard.HTTPClient(15 * time.Second).Do(req)

// Cap what you read back.
body, err := netguard.ReadCapped(resp.Body, 64<<10)
```

Validate at both ends: at config time for the error message, and again at call
time because the stored config may predate the guard or have been written by an
older release. `callWebhook` does both.

For protocols whose dialer we cannot hook, `ResolveHost` checks every address a
name resolves to. It is strictly weaker — the rebinding window is back — so use
it only where `Control` is unavailable, and say so at the call site.

## The escape hatch

`SUPERLOCK_ALLOW_PRIVATE_EGRESS=true` disables the address check entirely.

It exists because a self-hosted install may legitimately webhook to a service
on the same private network, and blocking that would make self-hosting useless.

**It must never be set on a multi-tenant deployment.** It restores the SSRF
primitive in full, for every tenant at once. `main.go` logs a warning at startup
when it is on; if that warning appears in a hosted environment's logs, treat it
as an incident.

`ParseURL` also relaxes to allow `http://` when the hatch is open, since
internal receivers frequently have no TLS. On the hosted product HTTPS is
required — a plaintext webhook would put the payload and the signature on the
wire in clear.

## Tests

`netguard_test.go` covers the blocklist including the IPv4-mapped forms, the
scheme rules, redirect refusal and the read cap. The one that matters most is
`TestHTTPClientBlocksLoopbackAtDial`: it stands up a real `httptest` server and
confirms the client refuses to reach it. A blocklist test that only calls
`CheckAddr` would pass even if the hook were never wired into the transport.
