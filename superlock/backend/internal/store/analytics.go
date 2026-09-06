package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
)

// WriteAccessLog records a secret access event for analytics.
func (s *Store) WriteAccessLog(ctx context.Context, secretID, orgID, actorID, envID uuid.UUID, actorType string) {
	go func() {
		_, _ = s.pool.Exec(context.Background(), `
			INSERT INTO secret_access_log (secret_id, org_id, actor_id, actor_type, env_id)
			VALUES ($1,$2,$3,$4,$5)`,
			secretID, orgID, actorID, actorType, envID)
	}()
}

// GetSecretHeatmap returns access frequency per secret in the last N days.
func (s *Store) GetSecretHeatmap(ctx context.Context, orgID uuid.UUID, days int) ([]*model.SecretHeatmapEntry, error) {
	since := time.Now().AddDate(0, 0, -days)
	rows, err := s.pool.Query(ctx, `
		SELECT
			l.secret_id,
			s.key        AS secret_key,
			l.env_id,
			e.name       AS env_name,
			COUNT(*)     AS count,
			MAX(l.accessed_at) AS last_access
		FROM secret_access_log l
		JOIN secrets s ON s.id = l.secret_id
		JOIN environments e ON e.id = l.env_id
		WHERE l.org_id = $1 AND l.accessed_at >= $2
		GROUP BY l.secret_id, s.key, l.env_id, e.name
		ORDER BY count DESC
		LIMIT 100`, orgID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.SecretHeatmapEntry
	for rows.Next() {
		var e model.SecretHeatmapEntry
		if err := rows.Scan(&e.SecretID, &e.SecretKey, &e.EnvID, &e.EnvName, &e.Count, &e.LastAccess); err != nil {
			continue
		}
		result = append(result, &e)
	}
	return result, nil
}

// GetUnusedSecrets returns secrets not accessed in the last N days.
func (s *Store) GetUnusedSecrets(ctx context.Context, orgID uuid.UUID, thresholdDays int) ([]*model.UnusedSecret, error) {
	threshold := time.Now().AddDate(0, 0, -thresholdDays)
	rows, err := s.pool.Query(ctx, `
		SELECT
			s.id         AS secret_id,
			s.key        AS secret_key,
			e.id         AS env_id,
			e.name       AS env_name,
			s.created_at,
			MAX(l.accessed_at) AS last_access,
			CASE
				WHEN MAX(l.accessed_at) IS NULL THEN NULL
				ELSE EXTRACT(DAY FROM NOW() - MAX(l.accessed_at))::INTEGER
			END AS days_since_access
		FROM secrets s
		JOIN environments e ON e.id = s.env_id
		JOIN projects p ON p.id = e.project_id
		LEFT JOIN secret_access_log l ON l.secret_id = s.id
		WHERE p.org_id = $1
		  AND s.deleted_at IS NULL
		GROUP BY s.id, s.key, e.id, e.name, s.created_at
		HAVING MAX(l.accessed_at) IS NULL OR MAX(l.accessed_at) < $2
		ORDER BY last_access ASC NULLS FIRST
		LIMIT 100`, orgID, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.UnusedSecret
	for rows.Next() {
		var u model.UnusedSecret
		if err := rows.Scan(&u.SecretID, &u.SecretKey, &u.EnvID, &u.EnvName,
			&u.CreatedAt, &u.LastAccess, &u.DaysSinceAccess); err != nil {
			continue
		}
		result = append(result, &u)
	}
	return result, nil
}

// GetAccessTimeSeries returns daily access counts for a secret over N days.
func (s *Store) GetAccessTimeSeries(ctx context.Context, secretID uuid.UUID, days int) ([]map[string]interface{}, error) {
	since := time.Now().AddDate(0, 0, -days)
	rows, err := s.pool.Query(ctx, `
		SELECT
			DATE(accessed_at) AS day,
			COUNT(*)          AS count
		FROM secret_access_log
		WHERE secret_id=$1 AND accessed_at >= $2
		GROUP BY DATE(accessed_at)
		ORDER BY day ASC`, secretID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var day time.Time
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"day":   day.Format("2006-01-02"),
			"count": count,
		})
	}
	return result, nil
}
