package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateProject(ctx context.Context, orgID, createdBy uuid.UUID, name, slug, description string) (*model.Project, error) {
	p := &model.Project{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO projects (id, org_id, name, slug, description, created_by)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
		RETURNING id, org_id, name, slug, description, created_by, created_at, updated_at
	`, orgID, name, slug, description, createdBy).Scan(
		&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	return p, nil
}

func (s *Store) GetProjectByID(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	p := &model.Project{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, org_id, name, slug, description, created_by, created_at, updated_at
		FROM projects WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

func (s *Store) ListProjectsByOrg(ctx context.Context, orgID uuid.UUID) ([]*model.Project, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, name, slug, description, created_by, created_at, updated_at
		FROM projects WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

func (s *Store) DeleteProject(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE projects SET deleted_at = NOW() WHERE id = $1`, id)
	return err
}

// Environments

func (s *Store) CreateEnvironment(ctx context.Context, projectID uuid.UUID, name, slug string, isProtected bool) (*model.Environment, error) {
	e := &model.Environment{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO environments (id, project_id, name, slug, is_protected)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
		RETURNING id, project_id, name, slug, is_protected, created_at
	`, projectID, name, slug, isProtected).Scan(
		&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.IsProtected, &e.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create environment: %w", err)
	}
	return e, nil
}

func (s *Store) GetEnvironmentByID(ctx context.Context, id uuid.UUID) (*model.Environment, error) {
	e := &model.Environment{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, project_id, name, slug, is_protected, created_at
		FROM environments WHERE id = $1
	`, id).Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.IsProtected, &e.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get environment: %w", err)
	}
	return e, nil
}

func (s *Store) ListEnvironmentsByProject(ctx context.Context, projectID uuid.UUID) ([]*model.Environment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, project_id, name, slug, is_protected, created_at
		FROM environments WHERE project_id = $1
		ORDER BY created_at ASC
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var envs []*model.Environment
	for rows.Next() {
		e := &model.Environment{}
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.IsProtected, &e.CreatedAt); err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}
	return envs, nil
}
