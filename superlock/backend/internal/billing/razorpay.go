package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nan0/backend/internal/model"
)

const rzpBaseURL = "https://api.razorpay.com/v1"

// Client wraps the Razorpay API.
type Client struct {
	keyID      string
	keySecret  string
	webhookSecret string
	httpClient *http.Client
}

// New creates a new Razorpay billing client.
func New(keyID, keySecret, webhookSecret string) *Client {
	return &Client{
		keyID:         keyID,
		keySecret:     keySecret,
		webhookSecret: webhookSecret,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}
}

// VerifyWebhookSignature validates the X-Razorpay-Signature header.
func (c *Client) VerifyWebhookSignature(payload []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(c.webhookSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// --- Webhook Types ---

type WebhookEvent struct {
	Entity    string          `json:"entity"`
	AccountID string          `json:"account_id"`
	Event     string          `json:"event"`
	Contains  []string        `json:"contains"`
	Payload   WebhookPayload  `json:"payload"`
	CreatedAt int64           `json:"created_at"`
}

type WebhookPayload struct {
	Subscription WebhookEntity `json:"subscription"`
	Payment      WebhookEntity `json:"payment"`
}

type WebhookEntity struct {
	Entity json.RawMessage `json:"entity"`
}

// Subscription represents a Razorpay subscription entity.
type Subscription struct {
	ID             string  `json:"id"`
	PlanID         string  `json:"plan_id"`
	CustomerID     string  `json:"customer_id"`
	Status         string  `json:"status"`
	Quantity       int     `json:"quantity"`
	CurrentStart   *int64  `json:"current_start"`
	CurrentEnd     *int64  `json:"current_end"`
	EndedAt        *int64  `json:"ended_at"`
	ShortURL       string  `json:"short_url"`
	HasScheduledChanges bool `json:"has_scheduled_changes"`
	Notes          map[string]string `json:"notes"`
}

// --- API Methods ---

// CreateSubscription creates a Razorpay subscription for the given plan.
func (c *Client) CreateSubscription(ctx context.Context, planID string, quantity int, orgID, email string) (*Subscription, error) {
	body := map[string]any{
		"plan_id":  planID,
		"quantity": quantity,
		"total_count": 120, // max billing cycles (10 years monthly)
		"notes": map[string]string{
			"org_id": orgID,
			"email":  email,
		},
	}

	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, rzpBaseURL+"/subscriptions", bytes.NewReader(b))
	req.SetBasicAuth(c.keyID, c.keySecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("razorpay subscription error %d: %s", resp.StatusCode, string(raw))
	}

	var sub Subscription
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

// CancelSubscription cancels a Razorpay subscription (at end of period).
func (c *Client) CancelSubscription(ctx context.Context, subscriptionID string, cancelAtEnd bool) error {
	body := map[string]any{
		"cancel_at_cycle_end": cancelAtEnd,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, rzpBaseURL+"/subscriptions/"+subscriptionID+"/cancel", bytes.NewReader(b))
	req.SetBasicAuth(c.keyID, c.keySecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("razorpay cancel error %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

// GetSubscription fetches a subscription by its ID.
func (c *Client) GetSubscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rzpBaseURL+"/subscriptions/"+subscriptionID, nil)
	req.SetBasicAuth(c.keyID, c.keySecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("razorpay get sub error %d: %s", resp.StatusCode, string(raw))
	}

	var sub Subscription
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

// PlanFromRazorpayPlanID maps a Razorpay Plan ID to our internal tier.
// Plan IDs should be configured via env vars.
func PlanFromRazorpayPlanID(planID, starterPlanID, businessPlanID string) (model.PlanTier, int) {
	switch planID {
	case starterPlanID:
		return model.PlanStarter, 90
	case businessPlanID:
		return model.PlanBusiness, 365
	default:
		return model.PlanFree, 7
	}
}
