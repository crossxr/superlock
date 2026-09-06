package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

// WriteAuditEvent appends an immutable audit event with HMAC chain.
func (s *Store) WriteAuditEvent(ctx context.Context, event *model.AuditEvent) error {
	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_events (id, org_id, actor_id, actor_type, action, resource_type, resource_id, metadata, ip_address, user_agent, ts, prev_hmac, hmac)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		event.OrgID, event.ActorID, event.ActorType, event.Action,
		event.ResourceType, event.ResourceID, metaJSON,
		event.IPAddress, event.UserAgent, event.Ts,
		event.PrevHMAC, event.HMAC,
	)
	if err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

// GetLastAuditHMAC returns the HMAC of the last event for the given org (for chain linking).
func (s *Store) GetLastAuditHMAC(ctx context.Context, orgID uuid.UUID) (string, string, error) {
	var id, hmac string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, hmac FROM audit_events WHERE org_id = $1 ORDER BY ts DESC LIMIT 1
	`, orgID).Scan(&id, &hmac)
	if err != nil {
		return "", "", nil // No previous event — start of chain
	}
	return id, hmac, nil
}

// ListAuditEvents returns paginated audit events for an org.
func (s *Store) ListAuditEvents(ctx context.Context, orgID uuid.UUID, limit, offset int, action string) ([]*model.AuditEvent, error) {
	query := `
		SELECT id, org_id, actor_id, actor_type, action, resource_type, resource_id, metadata, ip_address, user_agent, ts
		FROM audit_events
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argN := 2

	if action != "" {
		query += fmt.Sprintf(" AND action = $%d", argN)
		args = append(args, action)
		argN++
	}

	query += fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d OFFSET $%d", argN, argN+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.AuditEvent
	for rows.Next() {
		e := &model.AuditEvent{}
		var metaRaw []byte
		if err := rows.Scan(
			&e.ID, &e.OrgID, &e.ActorID, &e.ActorType, &e.Action,
			&e.ResourceType, &e.ResourceID, &metaRaw,
			&e.IPAddress, &e.UserAgent, &e.Ts,
		); err != nil {
			return nil, err
		}
		e.Metadata = metaRaw
		events = append(events, e)
	}
	return events, nil
}

// BuildAuditEvent creates an audit event struct ready to be saved.
func BuildAuditEvent(orgID, actorID uuid.UUID, actorType, action, resourceType string, resourceID *uuid.UUID, metadata map[string]interface{}, ip, ua string) *model.AuditEvent {
	metaJSON, _ := json.Marshal(metadata)
	return &model.AuditEvent{
		OrgID:        orgID,
		ActorID:      actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     metaJSON,
		IPAddress:    ip,
		UserAgent:    ua,
		Ts:           time.Now().UTC(),
	}
}
