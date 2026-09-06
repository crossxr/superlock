package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	u := &model.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_id, email, role, mfa_enabled, last_login_at, created_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	u := &model.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_id, email, role, mfa_enabled, last_login_at, created_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// UpsertUser creates or updates a user record (called on Supabase auth events).
func (s *Store) UpsertUser(ctx context.Context, id uuid.UUID, email string, orgID *uuid.UUID, role model.Role) (*model.User, error) {
	u := &model.User{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (id, org_id, email, role, last_login_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			email = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
			org_id = COALESCE(users.org_id, EXCLUDED.org_id),
			last_login_at = NOW(),
			updated_at = NOW()
		RETURNING id, org_id, email, role, mfa_enabled, last_login_at, created_at
	`, id, orgID, email, role).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.Role, &u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt,
	)
	if err != nil {
		fmt.Printf("DATABASE ERROR in UpsertUser: %v (ID: %s, Email: %s)\n", err, id, email)
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	return u, nil
}

func (s *Store) UpdateUserOrg(ctx context.Context, userID, orgID uuid.UUID, role model.Role) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET org_id = $1, role = $2, updated_at = NOW()
		WHERE id = $3
	`, orgID, role, userID)
	return err
}

func (s *Store) ListOrgUsers(ctx context.Context, orgID uuid.UUID) ([]*model.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, email, role, mfa_enabled, last_login_at, created_at
		FROM users WHERE org_id = $1 ORDER BY created_at ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		u := &model.User{}
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}
