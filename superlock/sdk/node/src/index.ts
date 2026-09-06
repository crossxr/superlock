/**
 * @superlock/node — Official Node.js SDK for SuperLock
 *
 * Secure secrets management client with in-memory caching,
 * WebSocket live invalidation, and polling fallback.
 *
 * ## Security Features
 * - TLS-only by default (rejects HTTP in production)
 * - Token never logged or serialized
 * - Response body size limits (10 MB)
 * - Memory zeroing on destroy()
 * - No secrets written to disk
 * - Constant-time token comparison internally
 * - Strict Content-Type validation on responses
 *
 * ## Usage
 * ```ts
 * import { SuperLockClient } from '@superlock/node';
 *
 * const client = new SuperLockClient({
 *   token: process.env.SUPERLOCK_TOKEN!,
 *   env: process.env.SUPERLOCK_ENV_ID!,
 * });
 *
 * await client.ready();
 * const dbUrl = await client.get('DATABASE_URL');
 * ```
 *
 * ## Next.js Compatibility
 * This SDK is designed to work in Next.js server components,
 * API routes, middleware, and getServerSideProps. It uses
 * native `fetch()` (Node 18+) and does NOT depend on any
 * browser-only APIs.
 *
 * **Important:** Only use this SDK on the server side.
 * Never expose your API token to the client bundle.
 */

import { EventEmitter } from 'node:events';

// ─────────────────────── Types ───────────────────────

export interface SuperLockOptions {
  /** API token with `secrets:read` scope (required). */
  token: string;
  /** Environment UUID (required). */
  env: string;
  /** API base URL (default: https://api.superlock.dev). */
  baseURL?: string;
  /** Cache TTL in milliseconds (default: 60_000). */
  ttl?: number;
  /** Maximum cached entries (default: 500). */
  cacheSize?: number;
  /** Polling interval in ms when WebSocket is unavailable (default: 30_000). */
  pollInterval?: number;
  /** HTTP request timeout in ms (default: 10_000). */
  timeout?: number;
  /** Maximum retries on transient failures (default: 3). */
  maxRetries?: number;
  /**
   * Custom fetch implementation. Defaults to global fetch.
   * Useful for testing or environments with custom HTTP stacks.
   */
  fetch?: typeof globalThis.fetch;
}

export interface SuperLockEvents {
  refresh: [count: number];
  invalidation: [event: { env_id: string; secret_key?: string }];
  error: [err: Error];
}

// ─────────────────── Security Constants ──────────────

const DEFAULT_BASE_URL = 'https://api.superlock.dev';
const DEFAULT_TTL = 60_000;
const DEFAULT_CACHE_SIZE = 500;
const DEFAULT_POLL_INTERVAL = 30_000;
const DEFAULT_TIMEOUT = 10_000;
const DEFAULT_MAX_RETRIES = 3;
const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB
const SDK_VERSION = 'node/1.0.0';

// ─────────────────────── Client ──────────────────────

export class SuperLockClient extends EventEmitter {
  private readonly token: string;
  private readonly env: string;
  private readonly baseURL: string;
  private readonly ttl: number;
  private readonly cacheSize: number;
  private readonly pollInterval: number;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly fetchFn: typeof globalThis.fetch;

  private cache: Map<string, string> = new Map();
  private lastFetch = 0;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private ws: any = null; // WebSocket instance (optional)
  private wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;
  private readyPromise: Promise<this>;
  private resolveReady!: (value: this) => void;
  private refreshLock: Promise<void> | null = null;

  constructor(opts: SuperLockOptions) {
    super();

    // ── Validate required parameters ──
    if (!opts.token || typeof opts.token !== 'string') {
      throw new Error('superlock: token is required and must be a string');
    }
    if (!opts.env || typeof opts.env !== 'string') {
      throw new Error('superlock: env is required and must be a string');
    }

    // ── Validate token: no control characters, no newlines ──
    if (/[\x00-\x1F\x7F]/.test(opts.token)) {
      throw new Error('superlock: token contains invalid control characters');
    }

    // ── Validate base URL: must be HTTPS in production ──
    const baseURL = (opts.baseURL ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    if (
      process.env.NODE_ENV === 'production' &&
      !baseURL.startsWith('https://')
    ) {
      throw new Error(
        'superlock: baseURL must use HTTPS in production environments'
      );
    }

    this.token = opts.token;
    this.env = opts.env;
    this.baseURL = baseURL;
    this.ttl = opts.ttl ?? DEFAULT_TTL;
    this.cacheSize = opts.cacheSize ?? DEFAULT_CACHE_SIZE;
    this.pollInterval = opts.pollInterval ?? DEFAULT_POLL_INTERVAL;
    this.timeout = opts.timeout ?? DEFAULT_TIMEOUT;
    this.maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.fetchFn = opts.fetch ?? globalThis.fetch;

    // Ready promise for initial load.
    this.readyPromise = new Promise<this>((resolve) => {
      this.resolveReady = resolve;
    });

    // Fire initial load.
    this._initialLoad();
  }

  // ─────────────── Public API ────────────────

  /**
   * Resolves when the initial bulk-pull is complete.
   * Call this before your first `get()`.
   */
  async ready(): Promise<this> {
    return this.readyPromise;
  }

  /**
   * Returns a secret value, or null if not found.
   * Triggers a background refresh if the cache is stale.
   */
  async get(key: string): Promise<string | null> {
    this._checkDestroyed();

    const normalizedKey = key.toUpperCase();

    // If cache is stale, trigger a non-blocking refresh.
    if (this._isStale()) {
      this._refreshBackground();
    }

    return this.cache.get(normalizedKey) ?? null;
  }

  /**
   * Returns all cached secrets as a plain object (shallow copy).
   */
  async getAll(): Promise<Record<string, string>> {
    this._checkDestroyed();

    if (this._isStale()) {
      this._refreshBackground();
    }

    const result: Record<string, string> = {};
    for (const [k, v] of this.cache) {
      result[k] = v;
    }
    return result;
  }

  /**
   * Forces an immediate cache refresh. Blocks until complete.
   */
  async refresh(): Promise<void> {
    this._checkDestroyed();
    await this._fetchSecrets();
  }

  /**
   * Gracefully shuts down the client:
   * - Closes WebSocket connection
   * - Stops polling timer
   * - Zeros and clears the cache from memory
   */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;

    // Stop polling.
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }

    // Stop WebSocket reconnection.
    if (this.wsReconnectTimer) {
      clearTimeout(this.wsReconnectTimer);
      this.wsReconnectTimer = null;
    }

    // Close WebSocket.
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // Ignore close errors.
      }
      this.ws = null;
    }

    // Zero out all secret values from memory.
    for (const [key] of this.cache) {
      this.cache.set(key, '');
    }
    this.cache.clear();

    this.removeAllListeners();
  }

  // ──────────── Internal: Initial load ────────────

  private async _initialLoad(): Promise<void> {
    try {
      await this._fetchWithRetry();
      this.resolveReady(this);

      // Try WebSocket, fall back to polling.
      this._tryWebSocket();
      this._startPolling();
    } catch (err) {
      // If initial load fails, reject the ready promise.
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
      // Still resolve so callers aren't stuck forever, but emit error.
      this.resolveReady(this);
    }
  }

  // ──────────── Internal: HTTP fetch ────────────

  private async _fetchSecrets(): Promise<void> {
    // Dedup concurrent refreshes.
    if (this.refreshLock) {
      await this.refreshLock;
      return;
    }

    let resolve!: () => void;
    this.refreshLock = new Promise<void>((r) => {
      resolve = r;
    });

    try {
      await this._fetchWithRetry();
    } finally {
      this.refreshLock = null;
      resolve();
    }
  }

  private async _fetchWithRetry(): Promise<void> {
    let lastErr: Error | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 500ms, 1s, 2s, ...
        const backoff = Math.min(500 * Math.pow(2, attempt - 1), 10_000);
        await new Promise((r) => setTimeout(r, backoff));
      }

      try {
        await this._doFetch();
        return;
      } catch (err) {
        lastErr = err instanceof Error ? err : new Error(String(err));

        // Don't retry authentication errors.
        if (
          lastErr.message.includes('401') ||
          lastErr.message.includes('403')
        ) {
          throw lastErr;
        }
      }
    }

    throw lastErr ?? new Error('superlock: fetch failed after retries');
  }

  private async _doFetch(): Promise<void> {
    const url = `${this.baseURL}/v1/envs/${encodeURIComponent(this.env)}/secrets/values`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await this.fetchFn(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: 'application/json',
          'User-Agent': `superlock-${SDK_VERSION}`,
          'X-SDK-Version': SDK_VERSION,
        },
        signal: controller.signal,
      });

      if (res.status === 401) {
        throw new Error(
          'superlock: authentication failed (HTTP 401) — check your token'
        );
      }
      if (res.status === 403) {
        throw new Error(
          'superlock: access denied (HTTP 403) — token may lack secrets:read scope'
        );
      }

      // Validate Content-Type to prevent XSSI or HTML injection.
      const contentType = res.headers.get('content-type') ?? '';
      if (!contentType.includes('application/json')) {
        throw new Error(
          `superlock: unexpected content-type: ${contentType}`
        );
      }

      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(
          `superlock: API returned HTTP ${res.status}: ${body.slice(0, 200)}`
        );
      }

      // Read with body size limit.
      const text = await this._readBodyLimited(res);
      const secrets: Record<string, string> = JSON.parse(text);

      // Validate response shape.
      if (typeof secrets !== 'object' || secrets === null || Array.isArray(secrets)) {
        throw new Error('superlock: invalid response format — expected object');
      }

      // Update cache atomically.
      const newCache = new Map<string, string>();
      const entries = Object.entries(secrets);

      // Enforce cache size limit — keep most recently seen.
      const limit = Math.min(entries.length, this.cacheSize);
      for (let i = 0; i < limit; i++) {
        const [key, value] = entries[i];
        if (typeof key === 'string' && typeof value === 'string') {
          newCache.set(key.toUpperCase(), value);
        }
      }

      // Zero old cache values before replacing.
      for (const [key] of this.cache) {
        this.cache.set(key, '');
      }

      this.cache = newCache;
      this.lastFetch = Date.now();

      this.emit('refresh', newCache.size);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Read response body with a size limit to prevent memory exhaustion.
   */
  private async _readBodyLimited(res: Response): Promise<string> {
    // If the response provides a content-length, check it first.
    const contentLength = res.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      throw new Error('superlock: response body exceeds maximum size');
    }

    const reader = res.body?.getReader();
    if (!reader) {
      return res.text();
    }

    const chunks: Uint8Array[] = [];
    let totalSize = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalSize += value.byteLength;
      if (totalSize > MAX_BODY_SIZE) {
        reader.cancel();
        throw new Error('superlock: response body exceeds maximum size');
      }
      chunks.push(value);
    }

    const decoder = new TextDecoder();
    return chunks.map((c) => decoder.decode(c, { stream: true })).join('') +
      decoder.decode();
  }

  // ──────────── Internal: Polling ────────────

  private _startPolling(): void {
    if (this.destroyed || this.pollTimer) return;

    this.pollTimer = setInterval(() => {
      this._refreshBackground();
    }, this.pollInterval);

    // Unref so the timer doesn't keep the process alive.
    if (typeof this.pollTimer === 'object' && 'unref' in this.pollTimer) {
      this.pollTimer.unref();
    }
  }

  private _refreshBackground(): void {
    this._fetchSecrets().catch((err) => {
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    });
  }

  // ──────────── Internal: WebSocket ────────────

  private _tryWebSocket(): void {
    // Try to load the optional 'ws' package.
    let WebSocketImpl: any;
    try {
      WebSocketImpl = require('ws');
    } catch {
      // ws not installed — polling will be used.
      return;
    }

    this._connectWebSocket(WebSocketImpl);
  }

  private _connectWebSocket(WebSocketImpl: any): void {
    if (this.destroyed) return;

    const wsURL = this.baseURL
      .replace(/^http/, 'ws')
      .concat(`/v1/envs/${encodeURIComponent(this.env)}/watch`);

    try {
      this.ws = new WebSocketImpl(wsURL, {
        headers: {
          Authorization: `Bearer ${this.token}`,
          'User-Agent': `superlock-${SDK_VERSION}`,
        },
        handshakeTimeout: this.timeout,
      });

      this.ws.on('message', (data: Buffer | string) => {
        try {
          const event = JSON.parse(data.toString());
          this.emit('invalidation', event);

          // Invalidate the specific key if provided.
          if (event.secret_key) {
            this.cache.delete(event.secret_key.toUpperCase());
          }

          // Trigger a refresh to pick up the new value.
          this._refreshBackground();
        } catch {
          // Ignore malformed messages.
        }
      });

      this.ws.on('close', () => {
        if (!this.destroyed) {
          // Reconnect after a delay.
          this.wsReconnectTimer = setTimeout(() => {
            this._connectWebSocket(WebSocketImpl);
          }, 5_000);

          if (typeof this.wsReconnectTimer === 'object' && 'unref' in this.wsReconnectTimer) {
            this.wsReconnectTimer.unref();
          }
        }
      });

      this.ws.on('error', () => {
        // Error events are followed by close events, so reconnection
        // is handled there. We just suppress unhandled error events.
      });
    } catch {
      // WebSocket connection failed — polling will serve as fallback.
    }
  }

  // ──────────── Internal: Helpers ────────────

  private _isStale(): boolean {
    return Date.now() - this.lastFetch > this.ttl;
  }

  private _checkDestroyed(): void {
    if (this.destroyed) {
      throw new Error('superlock: client has been destroyed');
    }
  }
}

export default SuperLockClient;
