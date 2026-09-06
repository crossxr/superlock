package rotation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/email"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/netguard"
	"github.com/nan0/backend/internal/pgsafe"
	"github.com/nan0/backend/internal/store"
	"github.com/nan0/backend/internal/ws"
	"github.com/redis/go-redis/v9"
)

type Worker struct {
	store  *store.Store
	crypto *crypto.Engine
	hub    *ws.Hub
	email  *email.Client
	rdb    *redis.Client
	guard  *netguard.Guard
}

func NewWorker(s *store.Store, c *crypto.Engine, h *ws.Hub, e *email.Client, rdb *redis.Client, g *netguard.Guard) *Worker {
	if g == nil {
		g = netguard.New(false)
	}
	return &Worker{store: s, crypto: c, hub: h, email: e, rdb: rdb, guard: g}
}

// Run starts the polling loop. Call in a goroutine.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	due, err := w.store.ListDueRotations(ctx)
	if err != nil {
		sentry.CaptureException(err)
		return
	}
	for _, sched := range due {
		go w.rotate(ctx, sched, "scheduler")
	}
}

// TriggerManual kicks off an immediate rotation for a secret.
func (w *Worker) TriggerManual(ctx context.Context, secretID uuid.UUID) error {
	sched, err := w.store.GetRotationScheduleBySecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("no rotation schedule: %w", err)
	}
	go w.rotate(context.Background(), sched, "manual")
	return nil
}

func (w *Worker) rotate(ctx context.Context, sched *model.RotationSchedule, triggeredBy string) {
	lockKey := fmt.Sprintf("nano:rotation:lock:%s", sched.SecretID)
	// Distributed lock via Redis SET NX EX 30
	if w.rdb != nil {
		ok, _ := w.rdb.SetNX(ctx, lockKey, "1", 30*time.Second).Result()
		if !ok {
			return // another instance has the lock
		}
		defer w.rdb.Del(ctx, lockKey)
	}

	histID := uuid.New()
	now := time.Now()
	hist := &model.RotationHistory{
		ID:          histID,
		SecretID:    sched.SecretID,
		ScheduleID:  &sched.ID,
		Status:      "pending",
		Backend:     string(sched.Backend),
		TriggeredBy: triggeredBy,
		StartedAt:   now,
	}
	_ = w.store.WriteRotationHistory(ctx, hist)

	// The secret's key and environment identify the rotation to the receiver.
	// Its value is never sent anywhere.
	secret, secretErr := w.store.GetSecretByID(ctx, sched.SecretID)
	if secretErr != nil || secret == nil {
		errMsg := "rotation: secret not found"
		hist.Status = "failed"
		hist.ErrorMsg = &errMsg
		finishedAt := time.Now()
		hist.FinishedAt = &finishedAt
		_ = w.store.WriteRotationHistory(ctx, hist)
		return
	}

	newValue, err := w.callBackend(ctx, sched, secret, histID)
	finishedAt := time.Now()

	if err != nil {
		errMsg := err.Error()
		hist.Status = "failed"
		hist.ErrorMsg = &errMsg
		hist.FinishedAt = &finishedAt
		_ = w.store.WriteRotationHistory(ctx, hist)
		sentry.CaptureException(err)
		w.alertOwners(ctx, sched.SecretID, errMsg)
		return
	}

	// Encrypt new value
	encVal, encDEK, encErr := w.crypto.Encrypt(newValue)
	if encErr != nil {
		sentry.CaptureException(encErr)
		return
	}

	// Write new version
	if err := w.store.RotateSecretValue(ctx, sched.SecretID, encVal, encDEK); err != nil {
		sentry.CaptureException(err)
		return
	}

	// Update schedule
	_ = w.store.UpdateRotationAfterSuccess(ctx, sched.ID, sched.IntervalHours)

	hist.Status = "success"
	hist.FinishedAt = &finishedAt
	_ = w.store.WriteRotationHistory(ctx, hist)

	// Broadcast WebSocket invalidation
	if w.hub != nil {
		w.hub.Broadcast(secret.EnvID.String(), ws.InvalidationEvent{
			Type:      "secret.rotated",
			EnvID:     secret.EnvID.String(),
			SecretKey: secret.Key,
		})
	}
}

// WebhookPayloadVersion identifies the request body format. Receivers should
// check it so a future change is detectable rather than silently misread.
const WebhookPayloadVersion = "2026-09-06"

const (
	webhookTimeout     = 15 * time.Second
	webhookMaxRespBody = 64 << 10 // 64 KiB
)

type webhookConfig struct {
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers"`
	SigningSecret string            `json:"signing_secret"`
}

// webhookPayload is what a rotation receiver is sent. It identifies which
// secret to rotate and nothing more — the current value is never included.
// A receiver that needs the outgoing value reads it through the API with its
// own credentials, which keeps the value inside an authenticated, audited path
// instead of being pushed to whatever URL the schedule happens to name.
type webhookPayload struct {
	Version     string `json:"version"`
	RotationID  string `json:"rotation_id"`
	SecretID    string `json:"secret_id"`
	Key         string `json:"key"`
	EnvID       string `json:"env_id"`
	Nonce       string `json:"nonce"`
	RequestedAt string `json:"requested_at"`
}

func (w *Worker) callBackend(ctx context.Context, sched *model.RotationSchedule, secret *model.Secret, rotationID uuid.UUID) (string, error) {
	switch sched.Backend {
	case model.RotationWebhook:
		return w.callWebhook(ctx, sched, secret, rotationID)
	case model.RotationPostgres:
		return w.rotatePostgresPassword(ctx, sched)
	default:
		return "", fmt.Errorf("unsupported backend: %s", sched.Backend)
	}
}

func (w *Worker) callWebhook(ctx context.Context, sched *model.RotationSchedule, secret *model.Secret, rotationID uuid.UUID) (string, error) {
	var cfg webhookConfig
	if err := json.Unmarshal(sched.ConfigJSON, &cfg); err != nil {
		return "", fmt.Errorf("invalid webhook config: %w", err)
	}

	// Re-validate the URL on every call: the address check is cheap, and the
	// config may predate the guard or have been written by an older release.
	if _, err := w.guard.ParseURL(cfg.URL); err != nil {
		return "", fmt.Errorf("webhook url rejected: %w", err)
	}

	nonce, err := crypto.GenerateSecureToken(16)
	if err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	body, err := json.Marshal(webhookPayload{
		Version:     WebhookPayloadVersion,
		RotationID:  rotationID.String(),
		SecretID:    sched.SecretID.String(),
		Key:         secret.Key,
		EnvID:       secret.EnvID.String(),
		Nonce:       nonce,
		RequestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("payload encoding failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("webhook request build failed: %w", err)
	}
	// Caller headers first, so they cannot override the ones we control.
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SuperLock-Rotation/1")
	if cfg.SigningSecret != "" {
		ts := time.Now().UTC().Unix()
		req.Header.Set("X-SuperLock-Signature", SignWebhook(cfg.SigningSecret, ts, body))
	}

	resp, err := w.guard.HTTPClient(webhookTimeout).Do(req)
	if err != nil {
		return "", fmt.Errorf("webhook call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	raw, err := netguard.ReadCapped(resp.Body, webhookMaxRespBody)
	if err != nil {
		return "", fmt.Errorf("webhook response rejected: %w", err)
	}

	var result struct {
		NewValue string `json:"new_value"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.NewValue == "" {
		return "", fmt.Errorf("webhook did not return new_value")
	}
	return result.NewValue, nil
}

// SignWebhook builds the X-SuperLock-Signature header value for a payload:
//
//	t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">
//
// The timestamp is inside the signed material so a receiver can reject replays
// by refusing signatures older than its own tolerance window.
func SignWebhook(signingSecret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

type postgresConfig struct {
	DSN      string `json:"dsn"`
	Username string `json:"username"`
}

func (w *Worker) rotatePostgresPassword(ctx context.Context, sched *model.RotationSchedule) (string, error) {
	var cfg postgresConfig
	if err := json.Unmarshal(sched.ConfigJSON, &cfg); err != nil {
		return "", fmt.Errorf("invalid postgres config: %w", err)
	}

	// ALTER ROLE takes no bind parameters, so the role name and password are
	// interpolated. Validate the name and quote both.
	if err := pgsafe.ValidateIdent(cfg.Username); err != nil {
		return "", fmt.Errorf("postgres rotation: invalid username: %w", err)
	}

	newPass := generatePassword(32)
	stmt := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s",
		pgsafe.QuoteIdent(cfg.Username), pgsafe.QuoteLiteral(newPass))

	if err := w.store.ExecRaw(ctx, cfg.DSN, stmt); err != nil {
		return "", fmt.Errorf("postgres rotation failed: %w", err)
	}
	return newPass, nil
}

func (w *Worker) alertOwners(ctx context.Context, secretID uuid.UUID, errMsg string) {
	if w.email == nil {
		return
	}
	secret, err := w.store.GetSecretByID(ctx, secretID)
	if err != nil || secret == nil {
		return
	}
	env, err := w.store.GetEnvironmentByID(ctx, secret.EnvID)
	if err != nil || env == nil {
		return
	}
	owners, err := w.store.GetOrgOwners(ctx, env.ProjectID)
	if err != nil {
		return
	}
	for _, owner := range owners {
		_ = w.email.SendRotationAlert(ctx, owner.Email, secret.Key, env.Name, errMsg)
	}
}

func generatePassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

	// Use crypto/rand
	return randomString(n, chars)
}
