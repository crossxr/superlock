package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckAddrBlocks(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"127.1.2.3",       // loopback, whole /8
		"10.0.0.1",        // RFC1918
		"172.16.5.9",      // RFC1918
		"192.168.1.1",     // RFC1918
		"169.254.169.254", // AWS/GCP metadata
		"169.254.1.1",     // link-local
		"100.64.0.1",      // CGNAT
		"0.0.0.0",         // unspecified
		"255.255.255.255", // broadcast
		"224.0.0.1",       // multicast
		"::1",             // IPv6 loopback
		"::",              // IPv6 unspecified
		"fd00::1",         // unique local
		"fe80::1",         // IPv6 link-local
		"fd00:ec2::254",   // EC2 IPv6 metadata
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
	}

	g := New(false)
	for _, s := range blocked {
		t.Run(s, func(t *testing.T) {
			addr := netip.MustParseAddr(s)
			if err := g.CheckAddr(addr); err == nil {
				t.Fatalf("CheckAddr(%s) = nil, want blocked", s)
			}
		})
	}
}

func TestCheckAddrAllowsPublic(t *testing.T) {
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}

	g := New(false)
	for _, s := range allowed {
		t.Run(s, func(t *testing.T) {
			if err := g.CheckAddr(netip.MustParseAddr(s)); err != nil {
				t.Fatalf("CheckAddr(%s) = %v, want nil", s, err)
			}
		})
	}
}

func TestAllowPrivateEscapeHatch(t *testing.T) {
	g := New(true)
	if err := g.CheckAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("with allowPrivate, CheckAddr = %v, want nil", err)
	}
}

func TestParseURL(t *testing.T) {
	g := New(false)

	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"https public host", "https://hooks.example.com/rotate", true},
		{"http rejected", "http://hooks.example.com/rotate", false},
		{"file rejected", "file:///etc/passwd", false},
		{"gopher rejected", "gopher://example.com/", false},
		{"no host", "https://", false},
		{"literal loopback", "https://127.0.0.1/x", false},
		{"literal metadata", "https://169.254.169.254/latest/meta-data/", false},
		{"literal private v6", "https://[fd00::1]/x", false},
		{"literal public", "https://1.1.1.1/x", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := g.ParseURL(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("ParseURL(%q) = %v, want nil", tc.in, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ParseURL(%q) = nil, want error", tc.in)
			}
		})
	}
}

// The dial-time hook is what actually stops a hostname that resolves to a
// private address, so exercise it against a real listener on loopback.
func TestHTTPClientBlocksLoopbackAtDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"new_value":"leaked"}`))
	}))
	defer srv.Close()

	client := New(false).HTTPClient(5 * time.Second)
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("request to loopback succeeded, want blocked")
	}
	if !strings.Contains(err.Error(), ErrBlockedAddress.Error()) {
		t.Fatalf("error = %v, want it to wrap ErrBlockedAddress", err)
	}
}

func TestHTTPClientAllowsLoopbackWhenPermitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(true).HTTPClient(5 * time.Second)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("with allowPrivate, request failed: %v", err)
	}
	resp.Body.Close()
}

func TestHTTPClientRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	}))
	defer srv.Close()

	// allowPrivate so the request reaches the handler; we are testing redirects.
	client := New(true).HTTPClient(5 * time.Second)
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("redirect was followed, want error")
	}
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("error = %v, want ErrRedirect", err)
	}
}

func TestReadCapped(t *testing.T) {
	if _, err := ReadCapped(strings.NewReader("hello"), 10); err != nil {
		t.Fatalf("under cap returned %v", err)
	}
	if _, err := ReadCapped(strings.NewReader("hello world"), 5); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("over cap returned %v, want ErrBodyTooLarge", err)
	}
	// Exactly at the cap must succeed.
	if _, err := ReadCapped(strings.NewReader("12345"), 5); err != nil {
		t.Fatalf("at cap returned %v", err)
	}
}
