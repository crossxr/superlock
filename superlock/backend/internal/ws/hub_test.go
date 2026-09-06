package ws

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestCheckOrigin(t *testing.T) {
	hub := NewHub([]string{"https://superlock.superxepic.dev", " https://staging.superlock.dev "})

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"no origin is a non-browser client", "", true},
		{"allowed origin", "https://superlock.superxepic.dev", true},
		{"allowed origin after trimming", "https://staging.superlock.dev", true},
		{"case-insensitive scheme and host", "HTTPS://SuperLock.superxepic.dev", true},

		{"hostile site", "https://evil.example", false},
		{"lookalike suffix", "https://superlock.superxepic.dev.evil.example", false},
		{"lookalike prefix", "https://evilsuperlock.superxepic.dev", false},
		{"right host wrong scheme", "http://superlock.superxepic.dev", false},
		{"null origin", "null", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/envs/abc/watch", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := hub.checkOrigin(r); got != tc.want {
				t.Fatalf("checkOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestCheckOriginEmptyAllowlistRejectsBrowsers(t *testing.T) {
	hub := NewHub(nil)

	r := httptest.NewRequest("GET", "/v1/envs/abc/watch", nil)
	r.Header.Set("Origin", "https://superlock.superxepic.dev")
	if hub.checkOrigin(r) {
		t.Fatal("empty allowlist accepted a browser origin")
	}

	// Non-browser clients still connect.
	if !hub.checkOrigin(httptest.NewRequest("GET", "/v1/envs/abc/watch", nil)) {
		t.Fatal("empty allowlist rejected a non-browser client")
	}
}

func TestCheckOriginWildcard(t *testing.T) {
	hub := NewHub([]string{"*"})
	r := httptest.NewRequest("GET", "/v1/envs/abc/watch", nil)
	r.Header.Set("Origin", "https://anything.example")
	if !hub.checkOrigin(r) {
		t.Fatal("wildcard allowlist rejected an origin")
	}
}

// Broadcast used to read the client set under a read lock, release it, and
// then send — racing unregister, which deletes from that same map and closes
// the channel under the write lock. This exercises both orderings under -race.
func TestBroadcastRacesUnregister(t *testing.T) {
	hub := NewHub(nil)
	const envID = "env-1"

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Continuously broadcast.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				hub.Broadcast(envID, InvalidationEvent{Type: "secret.updated", EnvID: envID})
			}
		}
	}()

	// Continuously register and unregister clients on the same env.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				c := &client{envID: envID, send: make(chan []byte, 1)}
				hub.register(c)
				hub.unregister(c)
			}
		}()
	}

	// Let the churn goroutines finish, then stop the broadcaster.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(200 * time.Millisecond)
	}()
	<-done
	close(stop)
	wg.Wait()
}

// A client whose buffer is full must be skipped, not block the broadcast.
func TestBroadcastDropsSlowClient(t *testing.T) {
	hub := NewHub(nil)
	const envID = "env-1"

	slow := &client{envID: envID, send: make(chan []byte, 1)}
	slow.send <- []byte("already full")
	hub.register(slow)

	fast := &client{envID: envID, send: make(chan []byte, 4)}
	hub.register(fast)

	hub.Broadcast(envID, InvalidationEvent{Type: "secret.updated", EnvID: envID})

	if len(fast.send) != 1 {
		t.Fatalf("fast client received %d messages, want 1", len(fast.send))
	}
	if len(slow.send) != 1 {
		t.Fatalf("slow client buffer = %d, want it left untouched at 1", len(slow.send))
	}
}
