package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const resendBaseURL = "https://api.resend.com"

type Client struct {
	apiKey    string
	fromEmail string
	fromName  string
	http      *http.Client
}

func New(apiKey, fromEmail, fromName string) *Client {
	return &Client{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		fromName:  fromName,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
}

type sendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

func (c *Client) send(ctx context.Context, to, subject, html string) error {
	body := sendRequest{
		From:    fmt.Sprintf("%s <%s>", c.fromName, c.fromEmail),
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resendBaseURL+"/emails", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("resend error: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) SendInvite(ctx context.Context, to, orgName, inviterEmail, inviteURL string) error {
	html := fmt.Sprintf(`
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:40px 20px">
  <h2 style="color:#4f46e5">You've been invited to %s on SuperLock</h2>
  <p>%s has invited you to join their organization on SuperLock — the secrets & config manager.</p>
  <a href="%s" style="display:inline-block;background:#4f46e5;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;margin:20px 0">
    Accept Invitation
  </a>
  <p style="color:#6b7280;font-size:14px">This invite expires in 7 days. If you did not expect this, you can ignore this email.</p>
</body></html>`, orgName, inviterEmail, inviteURL)
	return c.send(ctx, to, fmt.Sprintf("You've been invited to %s on SuperLock", orgName), html)
}

func (c *Client) SendRotationAlert(ctx context.Context, to, secretKey, envName, errMsg string) error {
	html := fmt.Sprintf(`
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:40px 20px">
  <h2 style="color:#ef4444">⚠ Rotation Failed: %s</h2>
  <p>The scheduled rotation for secret <strong>%s</strong> in environment <strong>%s</strong> failed.</p>
  <pre style="background:#f3f4f6;padding:16px;border-radius:6px;overflow:auto">%s</pre>
  <p>SuperLock will retry automatically with exponential backoff. Log in to manually trigger a rotation or review the rotation history.</p>
</body></html>`, secretKey, secretKey, envName, errMsg)
	return c.send(ctx, to, fmt.Sprintf("[SuperLock] Rotation failed for %s in %s", secretKey, envName), html)
}

func (c *Client) SendApprovalRequest(ctx context.Context, to, requesterEmail, secretKey, envName, approvalURL string) error {
	html := fmt.Sprintf(`
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:40px 20px">
  <h2 style="color:#f59e0b">🔐 Approval Required</h2>
  <p><strong>%s</strong> is requesting to write to the protected secret <strong>%s</strong> in <strong>%s</strong>.</p>
  <a href="%s" style="display:inline-block;background:#4f46e5;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;margin:20px 0">
    Review &amp; Approve
  </a>
  <p style="color:#6b7280;font-size:14px">This request expires in 24 hours.</p>
</body></html>`, requesterEmail, secretKey, envName, approvalURL)
	return c.send(ctx, to, fmt.Sprintf("[SuperLock] Approval needed for %s in %s", secretKey, envName), html)
}
