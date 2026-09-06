package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

func (s *Store) CreateRotationSchedule(ctx context.Context, secretID, createdBy uuid.UUID, intervalHours int, backend model.RotationBackend, cfg json.RawMessage) (*model.RotationSchedule, error) {
	next := time.Now().Add(time.Duration(intervalHours) * time.Hour)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO rotation_schedules (secret_id, interval_hours, backend, config_json, next_rotation_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, secret_id, interval_hours, backend, config_json, last_rotated_at,
		          next_rotation_at, enabled, created_by, created_at, updated_at`,
		secretID, intervalHours, backend, cfg, next, createdBy)

	var rs model.RotationSchedule
	if err := row.Scan(&rs.ID, &rs.SecretID, &rs.IntervalHours, &rs.Backend, &rs.ConfigJSON,
		&rs.LastRotatedAt, &rs.NextRotationAt, &rs.Enabled, &rs.CreatedBy, &rs.CreatedAt, &rs.UpdatedAt); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *Store) GetRotationScheduleBySecret(ctx context.Context, secretID uuid.UUID) (*model.RotationSchedule, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, secret_id, interval_hours, backend, config_json, last_rotated_at,
		       next_rotation_at, enabled, created_by, created_at, updated_at
		FROM rotation_schedules WHERE secret_id=$1`, secretID)
	var rs model.RotationSchedule
	if err := row.Scan(&rs.ID, &rs.SecretID, &rs.IntervalHours, &rs.Backend, &rs.ConfigJSON,
		&rs.LastRotatedAt, &rs.NextRotationAt, &rs.Enabled, &rs.CreatedBy, &rs.CreatedAt, &rs.UpdatedAt); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *Store) ListDueRotations(ctx context.Context) ([]*model.RotationSchedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, secret_id, interval_hours, backend, config_json, last_rotated_at,
		       next_rotation_at, enabled, created_by, created_at, updated_at
		FROM rotation_schedules
		WHERE enabled = TRUE AND next_rotation_at <= NOW()
		ORDER BY next_rotation_at ASC
		LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*model.RotationSchedule
	for rows.Next() {
		var rs model.RotationSchedule
		if err := rows.Scan(&rs.ID, &rs.SecretID, &rs.IntervalHours, &rs.Backend, &rs.ConfigJSON,
			&rs.LastRotatedAt, &rs.NextRotationAt, &rs.Enabled, &rs.CreatedBy, &rs.CreatedAt, &rs.UpdatedAt); err != nil {
			continue
		}
		result = append(result, &rs)
	}
	return result, nil
}

func (s *Store) UpdateRotationAfterSuccess(ctx context.Context, scheduleID uuid.UUID, intervalHours int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE rotation_schedules
		SET last_rotated_at = NOW(),
		    next_rotation_at = NOW() + ($2 * INTERVAL '1 hour'),
		    updated_at = NOW()
		WHERE id = $1`, scheduleID, intervalHours)
	return err
}

func (s *Store) DeleteRotationSchedule(ctx context.Context, scheduleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM rotation_schedules WHERE id=$1`, scheduleID)
	return err
}

func (s *Store) WriteRotationHistory(ctx context.Context, h *model.RotationHistory) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rotation_history (id, secret_id, schedule_id, status, backend, error_msg, triggered_by, started_at, finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		h.ID, h.SecretID, h.ScheduleID, h.Status, h.Backend, h.ErrorMsg, h.TriggeredBy, h.StartedAt, h.FinishedAt)
	return err
}

func (s *Store) ListRotationHistory(ctx context.Context, secretID uuid.UUID, limit int) ([]*model.RotationHistory, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, secret_id, schedule_id, status, backend, error_msg, triggered_by, started_at, finished_at
		FROM rotation_history WHERE secret_id=$1
		ORDER BY started_at DESC LIMIT $2`, secretID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.RotationHistory
	for rows.Next() {
		var h model.RotationHistory
		if err := rows.Scan(&h.ID, &h.SecretID, &h.ScheduleID, &h.Status, &h.Backend,
			&h.ErrorMsg, &h.TriggeredBy, &h.StartedAt, &h.FinishedAt); err != nil {
			continue
		}
		result = append(result, &h)
	}
	return result, nil
}

func (s *Store) GetRotationScheduleByID(ctx context.Context, scheduleID uuid.UUID) (*model.RotationSchedule, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, secret_id, interval_hours, backend, config_json, last_rotated_at,
		       next_rotation_at, enabled, created_by, created_at, updated_at
		FROM rotation_schedules WHERE id=$1`, scheduleID)
	var rs model.RotationSchedule
	if err := row.Scan(&rs.ID, &rs.SecretID, &rs.IntervalHours, &rs.Backend, &rs.ConfigJSON,
		&rs.LastRotatedAt, &rs.NextRotationAt, &rs.Enabled, &rs.CreatedBy, &rs.CreatedAt, &rs.UpdatedAt); err != nil {
		return nil, err
	}
	return &rs, nil
}
