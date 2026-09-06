package dev.superlock.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.Logger;

/**
 * SuperLockClient — Official Java SDK for SuperLock secrets manager.
 *
 * <pre>{@code
 * SuperLockClient client = SuperLockClient.builder()
 *     .token(System.getenv("SUPERLOCK_TOKEN"))
 *     .env(System.getenv("SUPERLOCK_ENV_ID"))
 *     .build();
 * String dbPass = client.get("DATABASE_PASSWORD");
 * }</pre>
 */
public class SuperLockClient implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(SuperLockClient.class.getName());
    private static final String DEFAULT_BASE_URL = "https://api.superlock.dev";
    private static final int DEFAULT_CACHE_SIZE = 500;
    private static final long DEFAULT_TTL_SECONDS = 60;

    private final String token;
    private final String envId;
    private final String baseUrl;
    private final long ttlSeconds;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "superlock-refresh");
        t.setDaemon(true);
        return t;
    });

    // LRU cache backed by LinkedHashMap
    private final Map<String, String> cache;
    private final AtomicLong cacheTimestamp = new AtomicLong(0);
    private final Object refreshLock = new Object();

    private SuperLockClient(Builder builder) {
        this.token = Objects.requireNonNull(builder.token, "token is required");
        this.envId = Objects.requireNonNull(builder.envId, "env is required");
        this.baseUrl = builder.baseUrl != null ? builder.baseUrl.replaceAll("/$", "") : DEFAULT_BASE_URL;
        this.ttlSeconds = builder.ttlSeconds > 0 ? builder.ttlSeconds : DEFAULT_TTL_SECONDS;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        int maxSize = builder.cacheSize > 0 ? builder.cacheSize : DEFAULT_CACHE_SIZE;
        this.cache = Collections.synchronizedMap(new LinkedHashMap<>(maxSize, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                return size() > maxSize;
            }
        });

        // Initial blocking pull
        refresh();

        // Schedule background polling every ttlSeconds
        scheduler.scheduleAtFixedRate(this::refresh, ttlSeconds, ttlSeconds, TimeUnit.SECONDS);
    }

    /** Returns the decrypted value for a key, or null if not found. */
    public String get(String key) {
        if (isStale()) refresh();
        return cache.get(key);
    }

    /** Returns all cached secrets as an unmodifiable map. */
    public Map<String, String> getAll() {
        if (isStale()) refresh();
        return Collections.unmodifiableMap(new HashMap<>(cache));
    }

    /** Returns the value or a default if the key is absent. */
    public String getOrDefault(String key, String defaultValue) {
        String val = get(key);
        return val != null ? val : defaultValue;
    }

    /** Forces an immediate cache refresh from the API. */
    public void refresh() {
        synchronized (refreshLock) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/envs/" + envId + "/secrets/values"))
                    .header("Authorization", "Bearer " + token)
                    .header("User-Agent", "superlock-java-sdk/3.0")
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();

                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> data = mapper.readValue(resp.body(), Map.class);
                    cache.clear();
                    cache.putAll(data);
                    cacheTimestamp.set(System.currentTimeMillis());
                    LOG.fine("SuperLock: refreshed " + data.size() + " secrets");
                } else {
                    LOG.warning("SuperLock: bulk pull returned " + resp.statusCode());
                }
            } catch (Exception e) {
                LOG.warning("SuperLock: refresh failed: " + e.getMessage());
            }
        }
    }

    /** Evicts a single key from cache (called on WebSocket invalidation). */
    public void evict(String key) {
        if (key != null) cache.remove(key);
        else cache.clear();
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }

    private boolean isStale() {
        return System.currentTimeMillis() - cacheTimestamp.get() > ttlSeconds * 1000;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String token;
        private String envId;
        private String baseUrl;
        private long ttlSeconds;
        private int cacheSize;

        public Builder token(String token) { this.token = token; return this; }
        public Builder env(String envId) { this.envId = envId; return this; }
        public Builder baseUrl(String baseUrl) { this.baseUrl = baseUrl; return this; }
        public Builder ttlSeconds(long ttlSeconds) { this.ttlSeconds = ttlSeconds; return this; }
        public Builder cacheSize(int cacheSize) { this.cacheSize = cacheSize; return this; }
        public SuperLockClient build() { return new SuperLockClient(this); }
    }
}