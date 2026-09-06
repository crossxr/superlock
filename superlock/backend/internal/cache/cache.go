package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Cache struct {
	client *redis.Client
}

func New(redisURL string) (*Cache, error) {
	if redisURL == "" {
		return nil, fmt.Errorf("REDIS_URL is required")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	client := redis.NewClient(opt)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &Cache{client: client}, nil
}

// IsTokenRevoked checks if an API token ID has been revoked.
func (c *Cache) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	if c == nil || c.client == nil {
		return false, nil
	}
	key := fmt.Sprintf("revoked:token:%s", tokenID)
	exists, err := c.client.Exists(ctx, key).Result()
	return exists > 0, err
}

// RevokeToken marks a token as revoked in Redis (TTL = 30 days).
func (c *Cache) RevokeToken(ctx context.Context, tokenID string) error {
	if c == nil || c.client == nil {
		return nil
	}
	key := fmt.Sprintf("revoked:token:%s", tokenID)
	return c.client.Set(ctx, key, "1", 30*24*time.Hour).Err()
}

// RateLimitCheck checks and increments rate limit counter.
// Returns (allowed, currentCount, error).
func (c *Cache) RateLimitCheck(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
	if c == nil || c.client == nil {
		return true, 0, nil
	}

	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)

	if _, err := pipe.Exec(ctx); err != nil {
		return true, 0, err // fail open on Redis error
	}

	count := incr.Val()
	return count <= limit, count, nil
}

// SetEnvEtag stores the current etag for an environment (used by SDK cache invalidation).
func (c *Cache) SetEnvEtag(ctx context.Context, envID, etag string) error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Set(ctx, fmt.Sprintf("etag:env:%s", envID), etag, 24*time.Hour).Err()
}

// GetEnvEtag retrieves the current etag for an environment.
func (c *Cache) GetEnvEtag(ctx context.Context, envID string) (string, error) {
	if c == nil || c.client == nil {
		return "", nil
	}
	return c.client.Get(ctx, fmt.Sprintf("etag:env:%s", envID)).Result()
}

// InvalidateEnvEtag removes the etag for an environment, forcing SDK refresh.
func (c *Cache) InvalidateEnvEtag(ctx context.Context, envID string) error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Del(ctx, fmt.Sprintf("etag:env:%s", envID)).Err()
}

// Add this method to the existing Cache struct

func (c *Cache) Raw() *redis.Client {
	if c == nil {
		return nil
	}
	return c.client
}
