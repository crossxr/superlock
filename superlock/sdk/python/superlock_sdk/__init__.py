"""SuperLock Python SDK — secrets & config manager client."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional
import urllib.request
import urllib.error
import json
import logging

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.superlock.dev"
DEFAULT_TTL = 60  # seconds
DEFAULT_CACHE_SIZE = 500


class _LRUCache:
    def __init__(self, maxsize: int):
        self._maxsize = maxsize
        self._store: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if key not in self._store:
                return None
            self._store.move_to_end(key)
            return self._store[key]

    def set(self, key: str, value: str) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            else:
                if len(self._store) >= self._maxsize:
                    self._store.popitem(last=False)
            self._store[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def items(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._store)


class SuperLockClient:
    """Thread-safe SuperLock secrets client with in-process LRU cache."""

    def __init__(
        self,
        token: str,
        env: str,
        base_url: str = DEFAULT_BASE_URL,
        ttl: int = DEFAULT_TTL,
        cache_size: int = DEFAULT_CACHE_SIZE,
        poll_interval: int = 30,
    ):
        if not token:
            raise ValueError("token is required")
        if not env:
            raise ValueError("env (environment ID) is required")

        self._token = token
        self._env_id = env
        self._base_url = base_url.rstrip("/")
        self._ttl = ttl
        self._cache = _LRUCache(cache_size)
        self._cache_ts: float = 0.0
        self._poll_interval = poll_interval
        self._ws_thread: Optional[threading.Thread] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        # Initial bulk pull (blocking)
        self._bulk_pull()
        # Start background refresh
        self._start_background()

    # ── Public API ──────────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[str]:
        """Return a secret value from cache, refreshing if TTL expired."""
        if time.time() - self._cache_ts > self._ttl:
            self._bulk_pull()
        return self._cache.get(key)

    def get_all(self) -> Dict[str, str]:
        """Return all cached secrets as a dict."""
        return self._cache.items()

    def refresh(self) -> None:
        """Force an immediate cache refresh from the API."""
        self._bulk_pull()

    def close(self) -> None:
        """Stop background threads."""
        self._stop.set()

    # ── Private ─────────────────────────────────────────────────────────────

    def _bulk_pull(self) -> None:
        try:
            data = self._request("GET", f"/v1/envs/{self._env_id}/secrets/values")
            if isinstance(data, dict):
                self._cache.clear()
                for k, v in data.items():
                    self._cache.set(k, str(v))
                self._cache_ts = time.time()
                logger.debug("SuperLock: refreshed %d secrets", len(data))
        except Exception as exc:
            logger.warning("SuperLock: bulk pull failed: %s", exc)

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = self._base_url + path
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": "superlock-python-sdk/2.0",
        }
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _start_background(self) -> None:
        # Try websocket, fall back to polling
        try:
            import websocket
            self._ws_thread = threading.Thread(target=self._ws_loop, daemon=True)
            self._ws_thread.start()
        except ImportError:
            logger.debug("SuperLock: websocket-client not installed, using polling")
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            self._bulk_pull()

    def _ws_loop(self) -> None:
        import websocket
        ws_url = (
            self._base_url.replace("https://", "wss://")
            .replace("http://", "ws://")
            + f"/v1/envs/{self._env_id}/watch"
        )

        def on_message(ws, message: str) -> None:
            try:
                event = json.loads(message)
                if event.get("env_id") == self._env_id:
                    if event.get("secret_key"):
                        self._cache.delete(event["secret_key"])
                    else:
                        self._cache.clear()
                    self._bulk_pull()
            except Exception:
                pass

        def on_error(ws, error) -> None:
            logger.debug("SuperLock WS error: %s", error)

        def on_close(ws, *args) -> None:
            if not self._stop.is_set():
                time.sleep(5)
                self._ws_loop()

        ws = websocket.WebSocketApp(
            ws_url,
            header={"Authorization": f"Bearer {self._token}"},
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        ws.run_forever()