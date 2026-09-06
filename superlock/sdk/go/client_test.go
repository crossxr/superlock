package superlock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSecrets is the mock response for the bulk-pull endpoint.
var fakeSecrets = map[string]string{
	"DATABASE_URL": "postgresql://user:pass@host/db",
	"API_KEY":      "sk_live_test123",
	"REDIS_URL":    "redis://localhost:6379",
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header is present and well-formed.
		auth := r.Header.Get("Authorization")
		if auth == "" || auth != "Bearer test-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		// Verify User-Agent.
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			t.Error("missing User-Agent header")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fakeSecrets)
	}))
}

func TestNew_RequiresTokenAndEnv(t *testing.T) {
	_, err := New()
	if err != ErrNotConfigured {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}

	_, err = New(WithToken("tok"))
	if err != ErrNotConfigured {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}

	_, err = New(WithEnv("env"))
	if err != ErrNotConfigured {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNew_RejectsInvalidTokenChars(t *testing.T) {
	_, err := New(
		WithToken("token\nwith\nnewlines"),
		WithEnv("env-id"),
		WithBaseURL("http://localhost"),
	)
	if err == nil {
		t.Error("expected error for token with newlines")
	}
}

func TestClient_GetAndGetAll(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithTTL(5*time.Minute),
		WithPollInterval(1*time.Hour), // Disable effective polling in test.
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	if !client.Ready() {
		t.Error("client should be ready after New()")
	}

	// Test Get.
	val, ok := client.Get("DATABASE_URL")
	if !ok || val != "postgresql://user:pass@host/db" {
		t.Errorf("Get(DATABASE_URL) = %q, %v; want %q, true", val, ok, "postgresql://user:pass@host/db")
	}

	// Test case insensitivity.
	val, ok = client.Get("database_url")
	if !ok || val != "postgresql://user:pass@host/db" {
		t.Errorf("Get(database_url) should be case-insensitive")
	}

	// Test missing key.
	_, ok = client.Get("NONEXISTENT")
	if ok {
		t.Error("Get(NONEXISTENT) should return false")
	}

	// Test GetAll.
	all := client.GetAll()
	if len(all) != len(fakeSecrets) {
		t.Errorf("GetAll() returned %d secrets, want %d", len(all), len(fakeSecrets))
	}

	// Verify GetAll returns a copy (mutation doesn't affect cache).
	all["NEW_KEY"] = "new_value"
	_, ok = client.Get("NEW_KEY")
	if ok {
		t.Error("mutating GetAll() result should not affect cache")
	}
}

func TestClient_MustGet_Panics(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithTTL(5*time.Minute),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	// Should not panic for existing key.
	val := client.MustGet("API_KEY")
	if val != "sk_live_test123" {
		t.Errorf("MustGet(API_KEY) = %q; want %q", val, "sk_live_test123")
	}

	// Should panic for missing key.
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGet(MISSING) should panic")
		}
	}()
	client.MustGet("MISSING_KEY")
}

func TestClient_GetOrDefault(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	val := client.GetOrDefault("API_KEY", "fallback")
	if val != "sk_live_test123" {
		t.Errorf("expected real value, got %q", val)
	}

	val = client.GetOrDefault("MISSING", "fallback")
	if val != "fallback" {
		t.Errorf("expected fallback, got %q", val)
	}
}

func TestClient_ConcurrentAccess(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Get("DATABASE_URL")
			_ = client.GetAll()
		}()
	}
	wg.Wait()
}

func TestClient_Refresh(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fakeSecrets)
	}))
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	initialCount := callCount.Load()

	ctx := context.Background()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	if callCount.Load() <= initialCount {
		t.Error("Refresh() should have triggered another API call")
	}
}

func TestClient_Close_ZerosMemory(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Verify secrets are present.
	_, ok := client.Get("DATABASE_URL")
	if !ok {
		t.Fatal("secret should exist before Close()")
	}

	client.Close()

	// After close, Get returns empty.
	_, ok = client.Get("DATABASE_URL")
	if ok {
		t.Error("Get should return false after Close()")
	}

	// Double close should be safe.
	client.Close()
}

func TestClient_CallbacksInvoked(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	var refreshCount atomic.Int32
	client, err := New(
		WithToken("test-token-123"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
		WithOnRefresh(func(count int) {
			refreshCount.Add(1)
		}),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer client.Close()

	if refreshCount.Load() < 1 {
		t.Error("onRefresh should have been called at least once")
	}
}

func TestClient_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	_, err := New(
		WithToken("bad-token"),
		WithEnv("test-env-id"),
		WithBaseURL(srv.URL),
		WithMaxRetries(0),
	)
	if err == nil {
		t.Error("expected error for unauthorized token")
	}
}

func TestClient_FromEnvVars(t *testing.T) {
	// Test that the client can be configured from environment variables
	// (this is a pattern test, not a full integration test).
	os.Setenv("SUPERLOCK_TOKEN", "test-token-123")
	os.Setenv("SUPERLOCK_ENV_ID", "test-env-id")
	defer os.Unsetenv("SUPERLOCK_TOKEN")
	defer os.Unsetenv("SUPERLOCK_ENV_ID")

	srv := newTestServer(t)
	defer srv.Close()

	client, err := New(
		WithToken(os.Getenv("SUPERLOCK_TOKEN")),
		WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
		WithBaseURL(srv.URL),
		WithPollInterval(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("New() from env vars failed: %v", err)
	}
	defer client.Close()

	val, ok := client.Get("API_KEY")
	if !ok || val != "sk_live_test123" {
		t.Errorf("expected API_KEY from env-var configured client")
	}
}
