package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

// ── Dynamic secret configs ───────────────────────────────────────────────────

func (s *Store) CreateDynamicConfig(ctx context.Context, envID, createdBy uuid.UUID, name string, backend model.DynamicBackend, cfg json.RawMessage) (*model.DynamicSecretConfig, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO dynamic_secret_configs (env_id, name, backend, config_json, created_by)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, env_id, name, backend, config_json, created_by, created_at, updated_at`,
		envID, name, backend, cfg, createdBy)
	return scanDynamicConfig(row)
}

func (s *Store) GetDynamicConfig(ctx context.Context, id uuid.UUID) (*model.DynamicSecretConfig, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, env_id, name, backend, config_json, created_by, created_at, updated_at
		FROM dynamic_secret_configs WHERE id=$1`, id)
	return scanDynamicConfig(row)
}

func (s *Store) ListDynamicConfigs(ctx context.Context, envID uuid.UUID) ([]*model.DynamicSecretConfig, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, env_id, name, backend, config_json, created_by, created_at, updated_at
		FROM dynamic_secret_configs WHERE env_id=$1 ORDER BY name`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.DynamicSecretConfig
	for rows.Next() {
		c, err := scanDynamicConfig(rows)
		if err != nil {
			continue
		}
		result = append(result, c)
	}
	return result, nil
}

func (s *Store) DeleteDynamicConfig(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM dynamic_secret_configs WHERE id=$1`, id)
	return err
}

func scanDynamicConfig(row interface{ Scan(...any) error }) (*model.DynamicSecretConfig, error) {
	var c model.DynamicSecretConfig
	err := row.Scan(&c.ID, &c.EnvID, &c.Name, &c.Backend, &c.ConfigJSON, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ── Dynamic secret leases ────────────────────────────────────────────────────

func (s *Store) CreateDynamicLease(ctx context.Context, orgID, configID, createdBy uuid.UUID, backend, username, databaseURL string, expiresAt time.Time) (*model.DynamicSecretLease, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO dynamic_secret_leases (org_id, backend, config_id, username, database_url, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, org_id, backend, config_id, username, database_url, expires_at, revoked_at, created_by, created_at`,
		orgID, backend, configID, username, databaseURL, expiresAt, createdBy)

	var l model.DynamicSecretLease
	err := row.Scan(&l.ID, &l.OrgID, &l.Backend, &l.ConfigID, &l.Username, &l.DatabaseURL,
		&l.ExpiresAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) ListExpiredLeases(ctx context.Context) ([]*model.DynamicSecretLease, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, backend, config_id, username, database_url, expires_at, revoked_at, created_by, created_at
		FROM dynamic_secret_leases
		WHERE expires_at <= NOW() AND revoked_at IS NULL
		LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.DynamicSecretLease
	for rows.Next() {
		var l model.DynamicSecretLease
		if err := rows.Scan(&l.ID, &l.OrgID, &l.Backend, &l.ConfigID, &l.Username, &l.DatabaseURL,
			&l.ExpiresAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt); err != nil {
			continue
		}
		result = append(result, &l)
	}
	return result, nil
}

func (s *Store) RevokeLease(ctx context.Context, leaseID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE dynamic_secret_leases SET revoked_at=NOW() WHERE id=$1`, leaseID)
	return err
}

func (s *Store) ListLeasesByOrg(ctx context.Context, orgID uuid.UUID) ([]*model.DynamicSecretLease, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, backend, config_id, username, database_url, expires_at, revoked_at, created_by, created_at
		FROM dynamic_secret_leases WHERE org_id=$1
		ORDER BY created_at DESC LIMIT 50`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.DynamicSecretLease
	for rows.Next() {
		var l model.DynamicSecretLease
		if err := rows.Scan(&l.ID, &l.OrgID, &l.Backend, &l.ConfigID, &l.Username, &l.DatabaseURL,
			&l.ExpiresAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt); err != nil {
			continue
		}
		// Never expose DSN in list
		l.DatabaseURL = ""
		result = append(result, &l)
	}
	return result, nil
}
