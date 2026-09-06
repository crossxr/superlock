package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateApproval(ctx context.Context, orgID, envID uuid.UUID, secretID *uuid.UUID, requestedBy uuid.UUID, action string, payload json.RawMessage) (*model.PendingApproval, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO pending_approvals (org_id, env_id, secret_id, requested_by, action, payload_json)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, org_id, env_id, secret_id, requested_by, approved_by, action, payload_json, status, expires_at, resolved_at, created_at`,
		orgID, envID, secretID, requestedBy, action, payload)

	var a model.PendingApproval
	if err := row.Scan(&a.ID, &a.OrgID, &a.EnvID, &a.SecretID, &a.RequestedBy, &a.ApprovedBy,
		&a.Action, &a.PayloadJSON, &a.Status, &a.ExpiresAt, &a.ResolvedAt, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) GetApproval(ctx context.Context, approvalID uuid.UUID) (*model.PendingApproval, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, org_id, env_id, secret_id, requested_by, approved_by, action, payload_json, status, expires_at, resolved_at, created_at
		FROM pending_approvals WHERE id=$1`, approvalID)
	var a model.PendingApproval
	if err := row.Scan(&a.ID, &a.OrgID, &a.EnvID, &a.SecretID, &a.RequestedBy, &a.ApprovedBy,
		&a.Action, &a.PayloadJSON, &a.Status, &a.ExpiresAt, &a.ResolvedAt, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListPendingApprovals(ctx context.Context, orgID uuid.UUID) ([]*model.PendingApproval, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, env_id, secret_id, requested_by, approved_by, action, payload_json, status, expires_at, resolved_at, created_at
		FROM pending_approvals
		WHERE org_id=$1 AND status='pending' AND expires_at > NOW()
		ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.PendingApproval
	for rows.Next() {
		var a model.PendingApproval
		if err := rows.Scan(&a.ID, &a.OrgID, &a.EnvID, &a.SecretID, &a.RequestedBy, &a.ApprovedBy,
			&a.Action, &a.PayloadJSON, &a.Status, &a.ExpiresAt, &a.ResolvedAt, &a.CreatedAt); err != nil {
			continue
		}
		result = append(result, &a)
	}
	return result, nil
}

func (s *Store) ResolveApproval(ctx context.Context, approvalID, resolverID uuid.UUID, status model.ApprovalStatus) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pending_approvals
		SET status=$2, approved_by=$3, resolved_at=NOW()
		WHERE id=$1 AND status='pending'`, approvalID, status, resolverID)
	return err
}
