package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateAPIToken(ctx context.Context, orgID, userID uuid.UUID, name, tokenHash string, scopes []string, expiresAt *time.Time, role model.Role) (*model.APIToken, error) {
	t := &model.APIToken{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (id, org_id, user_id, name, token_hash, scopes, expires_at, role)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7)
		RETURNING id, org_id, user_id, name, token_hash, scopes, last_used_at, expires_at, created_at, role
	`, orgID, userID, name, tokenHash, scopes, expiresAt, role).Scan(
		&t.ID, &t.OrgID, &t.UserID, &t.Name, &t.TokenHash, &t.Scopes, &t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("create api token: %w", err)
	}
	return t, nil
}

func (s *Store) GetAPITokenByHash(ctx context.Context, tokenHash string) (*model.APIToken, error) {
	t := &model.APIToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, name, token_hash, scopes, last_used_at, expires_at, created_at, role
		FROM api_tokens
		WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > NOW()) AND revoked_at IS NULL
	`, tokenHash).Scan(
		&t.ID, &t.OrgID, &t.UserID, &t.Name, &t.TokenHash, &t.Scopes, &t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.Role,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get api token: %w", err)
	}
	return t, nil
}

func (s *Store) ListAPITokensByUser(ctx context.Context, userID uuid.UUID) ([]*model.APIToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, user_id, name, token_hash, scopes, last_used_at, expires_at, created_at, role
		FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*model.APIToken
	for rows.Next() {
		t := &model.APIToken{}
		if err := rows.Scan(&t.ID, &t.OrgID, &t.UserID, &t.Name, &t.TokenHash, &t.Scopes, &t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.Role); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *Store) RevokeAPIToken(ctx context.Context, id, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

func (s *Store) TouchAPIToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}
