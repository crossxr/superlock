// Package netguard makes outbound requests to customer-supplied destinations
// safe to perform from inside our network.
//
// Rotation webhooks and dynamic-secret DSNs both take a URL or host from the
// customer and have the server connect to it. Without a guard that is a
// server-side request forgery primitive: the caller picks the address, our
// server supplies the network position, and the response (or the error text)
// is the oracle.
//
// The check runs in the dialer's Control hook rather than on a hostname
// resolved up front. By that point the address is the concrete IP the socket
// is about to connect to, so a DNS name that resolves to a public address on
// the first lookup and a private one on the second — DNS rebinding — is
// caught on the connection that matters.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	// ErrBlockedAddress is returned when a destination resolves to an address
	// range we refuse to connect to.
	ErrBlockedAddress = errors.New("destination address is not permitted")
	// ErrRedirect is returned when a destination attempts to redirect us.
	ErrRedirect = errors.New("redirects are not followed")
	// ErrScheme is returned for a non-HTTPS URL when HTTPS is required.
	ErrScheme = errors.New("url must use https")
	// ErrBodyTooLarge is returned when a response exceeds the read cap.
	ErrBodyTooLarge = errors.New("response body too large")
)

// blockedPrefixes are ranges that must never be reachable from a
// customer-controlled destination. Cloud metadata services (169.254.169.254,
// fd00:ec2::254) fall inside the link-local ranges.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),         // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local + cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),      // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),     // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("::1/128"),            // loopback
	netip.MustParsePrefix("fc00::/7"),           // unique local
	netip.MustParsePrefix("fe80::/10"),          // link-local
	netip.MustParsePrefix("ff00::/8"),           // multicast
}

// Guard decides which outbound destinations are permitted.
type Guard struct {
	// allowPrivate disables the address check. It exists for self-hosted
	// installs whose webhook receivers live on the same private network, and
	// is set from SUPERLOCK_ALLOW_PRIVATE_EGRESS. Never enable it on a
	// multi-tenant deployment: it restores the SSRF primitive in full.
	allowPrivate bool
}

// New returns a Guard. Pass allowPrivate only for single-tenant deployments.
func New(allowPrivate bool) *Guard { return &Guard{allowPrivate: allowPrivate} }

// AllowsPrivate reports whether the private-address check is disabled.
func (g *Guard) AllowsPrivate() bool { return g.allowPrivate }

// CheckAddr reports whether a single resolved address may be connected to.
func (g *Guard) CheckAddr(addr netip.Addr) error {
	if g.allowPrivate {
		return nil
	}
	// An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be compared against
	// the IPv4 ranges, not the IPv6 ones.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsValid() || addr.IsMulticast() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
		}
	}
	return nil
}

// ParseURL validates a customer-supplied URL before it is used. HTTPS is
// required unless private egress is enabled, since a plaintext webhook would
// expose the payload and the signature to the network path.
func (g *Guard) ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !g.allowPrivate {
			return nil, ErrScheme
		}
	default:
		return nil, ErrScheme
	}
	if u.Host == "" {
		return nil, errors.New("url has no host")
	}
	// A literal IP in the URL can be rejected immediately; hostnames are
	// checked at dial time.
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := g.CheckAddr(addr); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// HTTPClient returns a client that refuses blocked addresses at dial time and
// does not follow redirects. A redirect is rejected rather than followed
// because each hop would otherwise need its own check, and no legitimate
// webhook receiver needs one.
func (g *Guard) HTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparseable address %q", ErrBlockedAddress, address)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: unparseable ip %q", ErrBlockedAddress, host)
			}
			return g.CheckAddr(addr)
		},
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
			MaxIdleConns:          1,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return ErrRedirect
		},
	}
}

// ResolveHost checks every address a hostname resolves to. Use it for
// protocols whose dialer cannot be hooked; it is weaker than the Control hook
// because the name may resolve differently when the connection is made.
func (g *Guard) ResolveHost(ctx context.Context, host string) error {
	if g.allowPrivate {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.CheckAddr(addr)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: %q resolved to nothing", ErrBlockedAddress, host)
	}
	for _, a := range addrs {
		if err := g.CheckAddr(a); err != nil {
			return err
		}
	}
	return nil
}

// ReadCapped reads at most max bytes, returning ErrBodyTooLarge if the reader
// had more. It keeps a hostile endpoint from exhausting memory.
func ReadCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrBodyTooLarge
	}
	return b, nil
}
