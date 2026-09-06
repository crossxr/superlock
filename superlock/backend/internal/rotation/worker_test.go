package rotation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/netguard"
)

const plaintextSecret = "sk_live_THIS_MUST_NEVER_BE_SENT"

func testSecret() *model.Secret {
	return &model.Secret{
		ID:    uuid.New(),
		EnvID: uuid.New(),
		Key:   "STRIPE_KEY",
	}
}

// The whole point of the payload change: a rotation request identifies the
// secret, it never carries its value.
func TestWebhookPayloadOmitsSecretValue(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"new_value":"rotated"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(map[string]any{"url": srv.URL})
	w := &Worker{guard: netguard.New(true)} // allow loopback so the test server is reachable
	sched := &model.RotationSchedule{SecretID: uuid.New(), Backend: model.RotationWebhook, ConfigJSON: cfg}

	newValue, err := w.callWebhook(context.Background(), sched, testSecret(), uuid.New())
	if err != nil {
		t.Fatalf("callWebhook: %v", err)
	}
	if newValue != "rotated" {
		t.Fatalf("newValue = %q, want %q", newValue, "rotated")
	}

	if strings.Contains(string(got), plaintextSecret) {
		t.Fatal("payload contained the secret value")
	}
	// Guard against the old field name reappearing under any value.
	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if _, present := payload["old_value"]; present {
		t.Fatal("payload still carries old_value")
	}

	for _, field := range []string{"version", "rotation_id", "secret_id", "key", "env_id", "nonce", "requested_at"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("payload missing %q", field)
		}
	}
	if payload["version"] != WebhookPayloadVersion {
		t.Errorf("version = %v, want %v", payload["version"], WebhookPayloadVersion)
	}
}

func TestWebhookSignatureVerifies(t *testing.T) {
	const signingSecret = "whsec_testkey"

	var sigHeader string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-SuperLock-Signature")
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"new_value":"rotated"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(map[string]any{"url": srv.URL, "signing_secret": signingSecret})
	w := &Worker{guard: netguard.New(true)}
	sched := &model.RotationSchedule{SecretID: uuid.New(), Backend: model.RotationWebhook, ConfigJSON: cfg}

	if _, err := w.callWebhook(context.Background(), sched, testSecret(), uuid.New()); err != nil {
		t.Fatalf("callWebhook: %v", err)
	}

	// Verify exactly the way a receiver following the docs would.
	ts, v1, ok := parseSignature(sigHeader)
	if !ok {
		t.Fatalf("unparseable signature header %q", sigHeader)
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(v1), []byte(want)) {
		t.Fatalf("signature mismatch: got %s want %s", v1, want)
	}
	if drift := time.Since(time.Unix(ts, 0)); drift > time.Minute || drift < -time.Minute {
		t.Fatalf("timestamp drift %v, want it to be current", drift)
	}
}

func TestWebhookSignatureRejectsTamperedBody(t *testing.T) {
	const signingSecret = "whsec_testkey"
	body := []byte(`{"secret_id":"a"}`)
	ts := time.Now().Unix()

	header := SignWebhook(signingSecret, ts, body)
	_, v1, ok := parseSignature(header)
	if !ok {
		t.Fatalf("unparseable signature %q", header)
	}

	mac := hmac.New(sha256.New, []byte(signingSecret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write([]byte(`{"secret_id":"b"}`)) // attacker swapped the body
	tampered := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(v1), []byte(tampered)) {
		t.Fatal("signature validated a tampered body")
	}
}

// A schedule whose URL points at a private address must fail rather than
// connect, even though the config was accepted at some earlier time.
func TestWebhookRejectsPrivateDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"new_value":"leaked"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(map[string]any{"url": srv.URL})
	w := &Worker{guard: netguard.New(false)} // production posture
	sched := &model.RotationSchedule{SecretID: uuid.New(), Backend: model.RotationWebhook, ConfigJSON: cfg}

	if _, err := w.callWebhook(context.Background(), sched, testSecret(), uuid.New()); err == nil {
		t.Fatal("webhook to loopback succeeded, want rejection")
	}
}

func TestWebhookCallerHeadersCannotOverrideSignature(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-SuperLock-Signature")
		w.Write([]byte(`{"new_value":"rotated"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(map[string]any{
		"url":            srv.URL,
		"signing_secret": "whsec_testkey",
		"headers":        map[string]string{"X-SuperLock-Signature": "t=1,v1=forged"},
	})
	w := &Worker{guard: netguard.New(true)}
	sched := &model.RotationSchedule{SecretID: uuid.New(), Backend: model.RotationWebhook, ConfigJSON: cfg}

	if _, err := w.callWebhook(context.Background(), sched, testSecret(), uuid.New()); err != nil {
		t.Fatalf("callWebhook: %v", err)
	}
	if strings.Contains(sig, "forged") {
		t.Fatalf("caller header overrode the signature: %q", sig)
	}
}

func TestWebhookRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"new_value":"`))
		blob := strings.Repeat("A", 1024)
		for i := 0; i < 128; i++ { // 128 KiB, over the 64 KiB cap
			w.Write([]byte(blob))
		}
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(map[string]any{"url": srv.URL})
	w := &Worker{guard: netguard.New(true)}
	sched := &model.RotationSchedule{SecretID: uuid.New(), Backend: model.RotationWebhook, ConfigJSON: cfg}

	if _, err := w.callWebhook(context.Background(), sched, testSecret(), uuid.New()); err == nil {
		t.Fatal("oversized response accepted, want rejection")
	}
}

// parseSignature splits "t=<unix>,v1=<hex>" the way a receiver would.
func parseSignature(header string) (ts int64, v1 string, ok bool) {
	for _, part := range strings.Split(header, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch k {
		case "t":
			parsed, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, "", false
			}
			ts = parsed
		case "v1":
			v1 = v
		}
	}
	return ts, v1, ts != 0 && v1 != ""
}
