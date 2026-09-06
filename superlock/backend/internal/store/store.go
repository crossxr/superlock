package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nan0/backend/internal/model"
)

// Store wraps the pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Store connected to the given DATABASE_URL.
func New(databaseURL string) (*Store, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DB config: %w", err)
	}

	cfg.MaxConns = 10
	cfg.MinConns = 2

	// ── PgBouncer transaction-mode compatibility ──
	// PgBouncer in transaction mode reassigns server connections between
	// transactions. pgx's prepared statement cache creates statements on
	// the server, but after PgBouncer reassigns, those statements don't
	// exist on the new server connection → "already exists" errors.
	//
	// Fix: Use simple protocol (no prepared statements) AND disable all caches.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.ConnConfig.StatementCacheCapacity = 0
	cfg.ConnConfig.DescriptionCacheCapacity = 0

	// Also ensure no implicit prepared statements are used by the pool.
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("DB ping failed: %w", err)
	}

	return &Store{pool: pool}, nil
}

// Close closes the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Pool returns the underlying pool (for use in sub-packages).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// ExecRaw connects to an external DSN and runs a single statement.
// Used by the Postgres rotation backend.
func (s *Store) ExecRaw(ctx context.Context, dsn, query string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, query)
	return err
}

func (s *Store) GetOrgOwners(ctx context.Context, projectID uuid.UUID) ([]*model.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.org_id, u.email, u.role, u.mfa_enabled, u.last_login_at, u.created_at
		FROM users u
		JOIN projects p ON p.org_id = u.org_id
		WHERE p.id = $1 AND u.role IN ('owner', 'admin')`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt); err != nil {
			continue
		}
		result = append(result, &u)
	}
	return result, nil
}
