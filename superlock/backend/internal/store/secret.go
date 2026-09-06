package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateSecret(ctx context.Context, envID, createdBy uuid.UUID, key, encryptedValue, encryptedDEK string) (*model.Secret, error) {
	secret := &model.Secret{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO secrets (id, env_id, key, encrypted_value, encrypted_dek, version, created_by)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 1, $5)
		RETURNING id, env_id, key, encrypted_value, encrypted_dek, version, expires_at, created_by, created_at, updated_at
	`, envID, key, encryptedValue, encryptedDEK, createdBy).Scan(
		&secret.ID, &secret.EnvID, &secret.Key, &secret.EncryptedValue, &secret.EncryptedDEK,
		&secret.Version, &secret.ExpiresAt, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create secret: %w", err)
	}
	return secret, nil
}

func (s *Store) GetSecretByID(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	secret := &model.Secret{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, env_id, key, encrypted_value, encrypted_dek, version, expires_at, created_by, created_at, updated_at
		FROM secrets WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(
		&secret.ID, &secret.EnvID, &secret.Key, &secret.EncryptedValue, &secret.EncryptedDEK,
		&secret.Version, &secret.ExpiresAt, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return secret, nil
}

func (s *Store) GetSecretByKey(ctx context.Context, envID uuid.UUID, key string) (*model.Secret, error) {
	secret := &model.Secret{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, env_id, key, encrypted_value, encrypted_dek, version, expires_at, created_by, created_at, updated_at
		FROM secrets WHERE env_id = $1 AND key = $2 AND deleted_at IS NULL
	`, envID, key).Scan(
		&secret.ID, &secret.EnvID, &secret.Key, &secret.EncryptedValue, &secret.EncryptedDEK,
		&secret.Version, &secret.ExpiresAt, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get secret by key: %w", err)
	}
	return secret, nil
}

func (s *Store) ListSecretsByEnv(ctx context.Context, envID uuid.UUID) ([]*model.Secret, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, env_id, key, encrypted_value, encrypted_dek, version, expires_at, created_by, created_at, updated_at
		FROM secrets WHERE env_id = $1 AND deleted_at IS NULL
		ORDER BY key ASC
	`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []*model.Secret
	for rows.Next() {
		secret := &model.Secret{}
		if err := rows.Scan(
			&secret.ID, &secret.EnvID, &secret.Key, &secret.EncryptedValue, &secret.EncryptedDEK,
			&secret.Version, &secret.ExpiresAt, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (s *Store) UpdateSecret(ctx context.Context, id uuid.UUID, encryptedValue, encryptedDEK string) (*model.Secret, error) {
	secret := &model.Secret{}
	err := s.pool.QueryRow(ctx, `
		UPDATE secrets SET
			encrypted_value = $1,
			encrypted_dek = $2,
			version = version + 1,
			updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
		RETURNING id, env_id, key, encrypted_value, encrypted_dek, version, expires_at, created_by, created_at, updated_at
	`, encryptedValue, encryptedDEK, id).Scan(
		&secret.ID, &secret.EnvID, &secret.Key, &secret.EncryptedValue, &secret.EncryptedDEK,
		&secret.Version, &secret.ExpiresAt, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update secret: %w", err)
	}
	return secret, nil
}

func (s *Store) DeleteSecret(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE secrets SET deleted_at = NOW() WHERE id = $1`, id)
	return err
}

// SaveSecretVersion saves the current version before updating.
func (s *Store) SaveSecretVersion(ctx context.Context, secret *model.Secret) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO secret_versions (id, secret_id, encrypted_value, encrypted_dek, version, created_by)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
	`, secret.ID, secret.EncryptedValue, secret.EncryptedDEK, secret.Version, secret.CreatedBy)
	return err
}

func (s *Store) ListSecretVersions(ctx context.Context, secretID uuid.UUID) ([]*model.SecretVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, secret_id, encrypted_value, encrypted_dek, version, created_by, created_at
		FROM secret_versions WHERE secret_id = $1
		ORDER BY version DESC
	`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []*model.SecretVersion
	for rows.Next() {
		v := &model.SecretVersion{}
		if err := rows.Scan(&v.ID, &v.SecretID, &v.EncryptedValue, &v.EncryptedDEK, &v.Version, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, nil
}

// Add these methods to the existing store/secret.go

func (s *Store) RotateSecretValue(ctx context.Context, secretID uuid.UUID, encValue, encDEK string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Save current version to history
	var currentVersion int
	var currentEncValue, currentEncDEK string
	var createdBy uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT version, encrypted_value, encrypted_dek, created_by FROM secrets WHERE id=$1`, secretID).
		Scan(&currentVersion, &currentEncValue, &currentEncDEK, &createdBy)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO secret_versions (secret_id, encrypted_value, encrypted_dek, version, created_by)
		 VALUES ($1,$2,$3,$4,$5)`,
		secretID, currentEncValue, currentEncDEK, currentVersion, createdBy)
	if err != nil {
		return err
	}

	// Update secret with new value
	_, err = tx.Exec(ctx,
		`UPDATE secrets SET encrypted_value=$2, encrypted_dek=$3, version=version+1, updated_at=NOW()
		 WHERE id=$1`, secretID, encValue, encDEK)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
