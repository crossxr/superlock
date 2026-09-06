package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

func GenerateInviteToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = "inv_" + hex.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(h[:])
	return
}

func (s *Store) CreateInvitation(ctx context.Context, orgID uuid.UUID, email string, role model.Role, invitedBy uuid.UUID) (*model.Invitation, error) {
	plain, hash, err := GenerateInviteToken()
	if err != nil {
		return nil, err
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO invitations (org_id, email, role, token_hash, invited_by)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, org_id, email, role, token_hash, invited_by, accepted_at, expires_at, created_at`,
		orgID, email, role, hash, invitedBy)

	var inv model.Invitation
	if err := row.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.InvitedBy, &inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
		return nil, err
	}
	inv.PlainToken = plain
	return &inv, nil
}

func (s *Store) GetInvitationByToken(ctx context.Context, plainToken string) (*model.Invitation, error) {
	h := sha256.Sum256([]byte(plainToken))
	hash := hex.EncodeToString(h[:])

	row := s.pool.QueryRow(ctx, `
		SELECT id, org_id, email, role, token_hash, invited_by, accepted_at, expires_at, created_at
		FROM invitations
		WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at > NOW()`, hash)

	var inv model.Invitation
	if err := row.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.InvitedBy, &inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (s *Store) AcceptInvitation(ctx context.Context, invitationID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE invitations SET accepted_at=NOW() WHERE id=$1`, invitationID)
	return err
}

func (s *Store) ListInvitations(ctx context.Context, orgID uuid.UUID) ([]*model.Invitation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, email, role, token_hash, invited_by, accepted_at, expires_at, created_at
		FROM invitations WHERE org_id=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.Invitation
	for rows.Next() {
		var inv model.Invitation
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.TokenHash,
			&inv.InvitedBy, &inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			continue
		}
		result = append(result, &inv)
	}
	return result, nil
}

func (s *Store) RevokeInvitation(ctx context.Context, invitationID, orgID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM invitations WHERE id=$1 AND org_id=$2`, invitationID, orgID)
	return err
}
