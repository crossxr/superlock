// Package superlock provides a secure, production-grade Go client for the
// SuperLock secrets management platform.
//
// The client bulk-fetches all secrets for a given environment on startup,
// caches them in-memory with a configurable TTL, and keeps the cache fresh
// via background polling. Secrets are never written to disk.
//
// Usage:
//
//	client, err := superlock.New(
//	    superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
//	    superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	dbURL, ok := client.Get("DATABASE_URL")
//	all := client.GetAll()
package superlock

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// ───────────────────────────── Errors ──────────────────────────────

var (
	// ErrNotConfigured is returned when required configuration is missing.
	ErrNotConfigured = errors.New("superlock: token and env are required")
	// ErrNotReady is returned when secrets haven't been loaded yet.
	ErrNotReady = errors.New("superlock: client not ready — initial fetch pending")
	// ErrFetchFailed is returned when an API request fails.
	ErrFetchFailed = errors.New("superlock: failed to fetch secrets")
	// ErrShutdown is returned when operations are attempted on a closed client.
	ErrShutdown = errors.New("superlock: client is shut down")
)

// ───────────────────────────── Options ─────────────────────────────

const (
	defaultBaseURL      = "https://api.superlock.dev"
	defaultTTL          = 60 * time.Second
	defaultPollInterval = 30 * time.Second
	defaultTimeout      = 10 * time.Second
	defaultMaxRetries   = 3
	defaultMaxBodySize  = 10 << 20 // 10 MB
)

// Option configures the Client.
type Option func(*options)

type options struct {
	token        string
	env          string
	baseURL      string
	ttl          time.Duration
	pollInterval time.Duration
	timeout      time.Duration
	maxRetries   int
	httpClient   *http.Client
	onRefresh    func(count int)
	onError      func(err error)
	logger       Logger
}

// Logger is a minimal logging interface.
type Logger interface {
	Printf(format string, args ...interface{})
}

// WithToken sets the API token (required). Must have secrets:read scope.
func WithToken(token string) Option {
	return func(o *options) { o.token = strings.TrimSpace(token) }
}

// WithEnv sets the environment UUID (required).
func WithEnv(env string) Option {
	return func(o *options) { o.env = strings.TrimSpace(env) }
}

// WithBaseURL overrides the API base URL (default: https://api.superlock.dev).
func WithBaseURL(url string) Option {
	return func(o *options) { o.baseURL = strings.TrimRight(strings.TrimSpace(url), "/") }
}

// WithTTL sets how long cached values are considered fresh (default: 60s).
func WithTTL(d time.Duration) Option {
	return func(o *options) { o.ttl = d }
}

// WithPollInterval sets the background refresh interval (default: 30s).
func WithPollInterval(d time.Duration) Option {
	return func(o *options) { o.pollInterval = d }
}

// WithTimeout sets the HTTP request timeout (default: 10s).
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithMaxRetries sets the maximum number of retries on transient errors (default: 3).
func WithMaxRetries(n int) Option {
	return func(o *options) { o.maxRetries = n }
}

// WithHTTPClient provides a custom HTTP client. When set, WithTimeout is ignored.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

// WithOnRefresh registers a callback invoked after each successful cache refresh.
func WithOnRefresh(fn func(count int)) Option {
	return func(o *options) { o.onRefresh = fn }
}

// WithOnError registers a callback invoked when a background refresh fails.
func WithOnError(fn func(err error)) Option {
	return func(o *options) { o.onError = fn }
}

// WithLogger sets a logger for debug output. Nil disables logging (the default).
func WithLogger(l Logger) Option {
	return func(o *options) { o.logger = l }
}

// ───────────────────────────── Client ──────────────────────────────

// Client is a thread-safe, cached SuperLock secrets client.
type Client struct {
	opts options

	mu        sync.RWMutex
	secrets   map[string]string
	lastFetch time.Time
	ready     atomic.Bool
	closed    atomic.Bool

	group  singleflight.Group
	client *http.Client
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new Client, performs the initial bulk pull, and starts
// background polling. Returns an error if the initial fetch fails.
func New(opts ...Option) (*Client, error) {
	o := options{
		baseURL:      defaultBaseURL,
		ttl:          defaultTTL,
		pollInterval: defaultPollInterval,
		timeout:      defaultTimeout,
		maxRetries:   defaultMaxRetries,
	}
	for _, fn := range opts {
		fn(&o)
	}

	if o.token == "" || o.env == "" {
		return nil, ErrNotConfigured
	}

	// Sanitize the token — only allow printable ASCII, no newlines/control chars.
	for _, c := range o.token {
		if c < 0x20 || c > 0x7E {
			return nil, fmt.Errorf("superlock: token contains invalid characters")
		}
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: o.timeout,
			Transport: &http.Transport{
				TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConns:       10,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false,
				ForceAttemptHTTP2:  true,
			},
		}
	}

	c := &Client{
		opts:   o,
		client: httpClient,
		stopCh: make(chan struct{}),
	}

	// Initial fetch with retries.
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout*time.Duration(o.maxRetries+1))
	defer cancel()

	if err := c.fetchWithRetry(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	c.ready.Store(true)

	// Start background poller.
	c.wg.Add(1)
	go c.pollLoop()

	return c, nil
}

// Get returns the value associated with key, or ("", false) if not found.
// If the cache is stale, a background refresh is triggered (non-blocking).
func (c *Client) Get(key string) (string, bool) {
	if c.closed.Load() {
		return "", false
	}

	c.mu.RLock()
	val, ok := c.secrets[strings.ToUpper(key)]
	stale := time.Since(c.lastFetch) > c.opts.ttl
	c.mu.RUnlock()

	if stale {
		// Trigger non-blocking refresh (deduped via singleflight).
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), c.opts.timeout)
			defer cancel()
			_ = c.refreshOnce(ctx)
		}()
	}

	return val, ok
}

// MustGet returns the value associated with key, or panics if not found.
// Useful during application startup for required configuration.
func (c *Client) MustGet(key string) string {
	val, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("superlock: required secret %q not found", key))
	}
	return val
}

// GetOrDefault returns the value associated with key, or defaultVal if not found.
func (c *Client) GetOrDefault(key, defaultVal string) string {
	val, ok := c.Get(key)
	if !ok {
		return defaultVal
	}
	return val
}

// GetAll returns a shallow copy of all cached secrets.
func (c *Client) GetAll() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cp := make(map[string]string, len(c.secrets))
	for k, v := range c.secrets {
		cp[k] = v
	}
	return cp
}

// Refresh forces an immediate cache refresh. Blocks until complete.
func (c *Client) Refresh(ctx context.Context) error {
	if c.closed.Load() {
		return ErrShutdown
	}
	return c.refreshOnce(ctx)
}

// Ready returns true once the initial bulk pull has completed.
func (c *Client) Ready() bool {
	return c.ready.Load()
}

// Close stops background polling and releases resources.
// Safe to call multiple times.
func (c *Client) Close() {
	if c.closed.CompareAndSwap(false, true) {
		close(c.stopCh)
		c.wg.Wait()

		// Zero out the cached secrets from memory.
		c.mu.Lock()
		for k := range c.secrets {
			c.secrets[k] = ""
			delete(c.secrets, k)
		}
		c.secrets = nil
		c.mu.Unlock()
	}
}

// ────────────────────── Internal: HTTP fetch ───────────────────────

func (c *Client) buildRequest(ctx context.Context) (*http.Request, error) {
	url := fmt.Sprintf("%s/v1/envs/%s/secrets/values", c.opts.baseURL, c.opts.env)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.opts.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "superlock-go-sdk/1.0.0")
	req.Header.Set("X-SDK-Version", "go/1.0.0")

	return req, nil
}

func (c *Client) doFetch(ctx context.Context) (map[string]string, error) {
	req, err := c.buildRequest(ctx)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, req.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("parse secrets JSON: %w", err)
	}

	return secrets, nil
}

func (c *Client) fetchWithRetry(ctx context.Context) error {
	var lastErr error

	for attempt := 0; attempt <= c.opts.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 200 * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		secrets, err := c.doFetch(ctx)
		if err == nil {
			c.mu.Lock()
			c.secrets = secrets
			c.lastFetch = time.Now()
			c.mu.Unlock()
			if c.opts.onRefresh != nil {
				c.opts.onRefresh(len(secrets))
			}
			return nil
		}

		lastErr = err
		c.logf("fetch attempt %d/%d failed: %v", attempt+1, c.opts.maxRetries+1, err)
	}

	return lastErr
}

func (c *Client) refreshOnce(ctx context.Context) error {
	_, err, _ := c.group.Do("refresh", func() (any, error) {
		secrets, err := c.doFetch(ctx)
		if err != nil {
			if c.opts.onError != nil {
				c.opts.onError(err)
			}
			return nil, err
		}

		c.mu.Lock()
		c.secrets = secrets
		c.lastFetch = time.Now()
		count := len(secrets)
		c.mu.Unlock()

		if c.opts.onRefresh != nil {
			c.opts.onRefresh(count)
		}

		return nil, nil
	})

	return err
}

// ────────────────────── Internal: Background poll ──────────────────

func (c *Client) pollLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.opts.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), c.opts.timeout)
			if err := c.refreshOnce(ctx); err != nil {
				c.logf("background refresh failed: %v", err)
			}
			cancel()
		}
	}
}

func (c *Client) logf(format string, args ...interface{}) {
	if c.opts.logger != nil {
		c.opts.logger.Printf("[superlock] "+format, args...)
	}
}
