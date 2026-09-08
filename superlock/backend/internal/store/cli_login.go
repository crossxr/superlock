package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

// CreateCLILoginCode persists a one-time PKCE code for a CLI login attempt.
func (s *Store) CreateCLILoginCode(ctx context.Context, orgID, userID uuid.UUID, role model.Role, codeHash, codeChallenge string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cli_login_codes (id, org_id, user_id, role, code_hash, code_challenge, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
	`, orgID, userID, role, codeHash, codeChallenge, expiresAt)
	if err != nil {
		return fmt.Errorf("create cli login code: %w", err)
	}
	return nil
}

// ClaimCLILoginCode atomically marks a code used and returns it in the same
// statement, so two concurrent exchange attempts for the same code cannot
// both succeed — the loser sees no row rather than a code someone else has
// already spent.
func (s *Store) ClaimCLILoginCode(ctx context.Context, codeHash string) (*model.CLILoginCode, error) {
	c := &model.CLILoginCode{}
	err := s.pool.QueryRow(ctx, `
		UPDATE cli_login_codes
		SET used_at = NOW()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING id, org_id, user_id, role, code_hash, code_challenge, used_at, expires_at, created_at
	`, codeHash).Scan(
		&c.ID, &c.OrgID, &c.UserID, &c.Role, &c.CodeHash, &c.CodeChallenge, &c.UsedAt, &c.ExpiresAt, &c.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim cli login code: %w", err)
	}
	return c, nil
}
