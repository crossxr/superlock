package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

// CreateSharedSecret inserts a new shared secret link.
func (s *Store) CreateSharedSecret(ctx context.Context, orgID, createdBy uuid.UUID, label, secretsEnc, encryptedDEK string, expiresAt string, maxViews int) (*model.SharedSecret, error) {
	ss := &model.SharedSecret{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO shared_secrets (id, org_id, created_by, label, secrets_enc, encrypted_dek, expires_at, max_views)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::TIMESTAMPTZ, $7)
		RETURNING id, org_id, created_by, label, expires_at, max_views, view_count, created_at
	`, orgID, createdBy, label, secretsEnc, encryptedDEK, expiresAt, maxViews).Scan(
		&ss.ID, &ss.OrgID, &ss.CreatedBy, &ss.Label, &ss.ExpiresAt, &ss.MaxViews, &ss.ViewCount, &ss.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create shared secret: %w", err)
	}
	return ss, nil
}

// GetSharedSecret fetches a shared secret by ID and increments view count.
func (s *Store) GetSharedSecret(ctx context.Context, id uuid.UUID) (*model.SharedSecret, error) {
	ss := &model.SharedSecret{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_id, created_by, label, secrets_enc, encrypted_dek, expires_at, max_views, view_count, created_at
		FROM shared_secrets
		WHERE id = $1
	`, id).Scan(
		&ss.ID, &ss.OrgID, &ss.CreatedBy, &ss.Label, &ss.SecretsEnc, &ss.EncryptedDEK,
		&ss.ExpiresAt, &ss.MaxViews, &ss.ViewCount, &ss.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get shared secret: %w", err)
	}
	return ss, nil
}

// IncrementShareViewCount atomically increments the view count and returns the new count.
func (s *Store) IncrementShareViewCount(ctx context.Context, id uuid.UUID) (int, error) {
	var newCount int
	err := s.pool.QueryRow(ctx, `
		UPDATE shared_secrets SET view_count = view_count + 1 WHERE id = $1
		RETURNING view_count
	`, id).Scan(&newCount)
	return newCount, err
}

// ListSharedSecretsByOrg returns shared secrets for an org (metadata only).
func (s *Store) ListSharedSecretsByOrg(ctx context.Context, orgID uuid.UUID) ([]*model.SharedSecret, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, created_by, label, expires_at, max_views, view_count, created_at
		FROM shared_secrets WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*model.SharedSecret
	for rows.Next() {
		ss := &model.SharedSecret{}
		if err := rows.Scan(
			&ss.ID, &ss.OrgID, &ss.CreatedBy, &ss.Label, &ss.ExpiresAt, &ss.MaxViews, &ss.ViewCount, &ss.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, ss)
	}
	return items, nil
}

// DeleteSharedSecret removes a shared link.
func (s *Store) DeleteSharedSecret(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM shared_secrets WHERE id = $1`, id)
	return err
}
