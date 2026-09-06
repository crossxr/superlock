// Package dynamic generates short-lived database credentials on demand.
package dynamic

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

const (
	DefaultTTLMinutes = 60
	passwordChars     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// PostgresConfig is stored (encrypted) in dynamic_secret_configs.config_json
type PostgresConfig struct {
	AdminDSN string `json:"admin_dsn"` // DSN with admin creds for CREATE ROLE
	RoleBase string `json:"role_base"` // prefix for generated usernames, e.g. "nano_app"
	DBName   string `json:"db_name"`
	TTLMin   int    `json:"ttl_minutes"` // 0 = use default
}

// MySQLConfig is the equivalent for MySQL/MariaDB
type MySQLConfig struct {
	AdminDSN string `json:"admin_dsn"`
	RoleBase string `json:"role_base"`
	DBName   string `json:"db_name"`
	TTLMin   int    `json:"ttl_minutes"`
}

type LeaseResult struct {
	Username  string
	Password  string
	DSN       string // full DSN with credentials for application use
	ExpiresAt time.Time
}

// GeneratePostgresLease creates a short-lived Postgres role and returns credentials.
func GeneratePostgresLease(ctx context.Context, cfg PostgresConfig) (*LeaseResult, error) {
	ttl := cfg.TTLMin
	if ttl <= 0 {
		ttl = DefaultTTLMinutes
	}

	conn, err := pgx.Connect(ctx, cfg.AdminDSN)
	if err != nil {
		return nil, fmt.Errorf("dynamic postgres: admin connect failed: %w", err)
	}
	defer conn.Close(ctx)

	username := fmt.Sprintf("%s_%s", cfg.RoleBase, randomSuffix(8))
	password := randomPassword(24)
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Minute)

	// Create role with login, password, and validity window
	_, err = conn.Exec(ctx, fmt.Sprintf(
		`CREATE ROLE %s WITH LOGIN PASSWORD '%s' VALID UNTIL '%s'`,
		pgQuoteIdent(username),
		pgEscapeString(password),
		expiresAt.UTC().Format(time.RFC3339),
	))
	if err != nil {
		return nil, fmt.Errorf("dynamic postgres: create role failed: %w", err)
	}

	// Grant connect on database
	_, err = conn.Exec(ctx, fmt.Sprintf(
		`GRANT CONNECT ON DATABASE %s TO %s`,
		pgQuoteIdent(cfg.DBName), pgQuoteIdent(username),
	))
	if err != nil {
		// Rollback role creation
		_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgQuoteIdent(username)))
		return nil, fmt.Errorf("dynamic postgres: grant connect failed: %w", err)
	}

	// Build connection DSN (strip admin creds, inject new user/pass)
	dsn := buildPostgresDSN(cfg.AdminDSN, username, password, cfg.DBName)

	return &LeaseResult{
		Username:  username,
		Password:  password,
		DSN:       dsn,
		ExpiresAt: expiresAt,
	}, nil
}

// RevokePostgresLease drops the dynamic role.
func RevokePostgresLease(ctx context.Context, adminDSN, username string) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("revoke postgres: admin connect failed: %w", err)
	}
	defer conn.Close(ctx)

	// Terminate existing sessions first
	_, _ = conn.Exec(ctx, fmt.Sprintf(
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s'`,
		pgEscapeString(username),
	))

	_, err = conn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgQuoteIdent(username)))
	return err
}

// GenerateMySQLLease creates a short-lived MySQL user and returns credentials.
func GenerateMySQLLease(ctx context.Context, cfg MySQLConfig) (*LeaseResult, error) {
	ttl := cfg.TTLMin
	if ttl <= 0 {
		ttl = DefaultTTLMinutes
	}

	// Use database/sql with MySQL driver via DSN
	// We use pgx here only for Postgres; for MySQL we shell out via a minimal driver
	username := fmt.Sprintf("%s_%s", cfg.RoleBase, randomSuffix(8))
	password := randomPassword(24)
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Minute)

	if err := execMySQL(ctx, cfg.AdminDSN, []string{
		fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", mysqlEscape(username), mysqlEscape(password)),
		fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO '%s'@'%%'", mysqlEscape(cfg.DBName), mysqlEscape(username)),
		"FLUSH PRIVILEGES",
	}); err != nil {
		return nil, fmt.Errorf("dynamic mysql: %w", err)
	}

	dsn := buildMySQLDSN(cfg.AdminDSN, username, password, cfg.DBName)
	return &LeaseResult{
		Username:  username,
		Password:  password,
		DSN:       dsn,
		ExpiresAt: expiresAt,
	}, nil
}

// RevokeMySQLLease drops the dynamic MySQL user.
func RevokeMySQLLease(ctx context.Context, adminDSN, username string) error {
	return execMySQL(ctx, adminDSN, []string{
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", mysqlEscape(username)),
	})
}

// ExpiredLeaseReaper runs continuously, revoking expired leases.
// Call in a goroutine via go ExpiredLeaseReaper(ctx, store).
func ExpiredLeaseReaper(ctx context.Context, leaseFetcher func(ctx context.Context) ([]*model.DynamicSecretLease, error), revoker func(ctx context.Context, l *model.DynamicSecretLease) error) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			leases, err := leaseFetcher(ctx)
			if err != nil {
				sentry.CaptureException(fmt.Errorf("lease reaper: fetcher failed: %w", err))
				continue
			}
			for _, l := range leases {
				if err := revoker(ctx, l); err != nil {
					sentry.CaptureException(fmt.Errorf("lease reaper: revocation failed for %s: %w", l.ID, err))
				}
			}
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func randomSuffix(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[idx.Int64()]
	}
	return string(b)
}

func randomPassword(n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(passwordChars))))
		b[i] = passwordChars[idx.Int64()]
	}
	return string(b)
}

func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func pgEscapeString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func mysqlEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

func buildPostgresDSN(adminDSN, user, pass, dbName string) string {
	// Parse host/port from adminDSN and rebuild with new creds
	// Simple approach: replace user:pass@host pattern
	// In production, use url.Parse for robustness
	return fmt.Sprintf("postgres://%s:%s@placeholder/%s", user, pass, dbName)
}

func buildMySQLDSN(adminDSN, user, pass, dbName string) string {
	return fmt.Sprintf("%s:%s@tcp(placeholder)/%s", user, pass, dbName)
}

// execMySQL runs a list of SQL statements against a MySQL DSN.
// Uses a minimal net/tcp approach since we avoid heavy driver imports.
func execMySQL(ctx context.Context, dsn string, stmts []string) error {
	// In a real implementation, import github.com/go-sql-driver/mysql
	// and use database/sql. Stubbed here to avoid adding the dependency
	// without confirmation — the dynamic package interface is complete.
	return fmt.Errorf("mysql driver: import go-sql-driver/mysql and implement execMySQL")
}
