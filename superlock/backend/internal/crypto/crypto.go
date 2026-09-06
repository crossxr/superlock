package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Engine handles all encryption/decryption using envelope encryption.
// Phase 1: KEK is from environment variable.
// Phase 2: KEK will be wrapped by Cloud KMS.
type Engine struct {
	kek []byte // 32-byte Key Encryption Key
}

// New creates a new encryption engine. kekBase64 must be a base64-encoded 32-byte key.
func New(kekBase64 string) (*Engine, error) {
	kek, err := base64.StdEncoding.DecodeString(kekBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid KEK encoding: %w", err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(kek))
	}
	return &Engine{kek: kek}, nil
}

// Encrypt encrypts plaintext using envelope encryption.
// Returns: encryptedValue (base64), encryptedDEK (base64), error
func (e *Engine) Encrypt(plaintext string) (encryptedValue, encryptedDEK string, err error) {
	// Generate a fresh 32-byte DEK
	dek := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, dek); err != nil {
		return "", "", fmt.Errorf("DEK generation failed: %w", err)
	}

	// Encrypt the plaintext with the DEK using AES-256-GCM
	ciphertext, err := aesGCMEncrypt(dek, []byte(plaintext))
	if err != nil {
		return "", "", fmt.Errorf("value encryption failed: %w", err)
	}

	// Wrap the DEK with the KEK
	wrappedDEK, err := aesGCMEncrypt(e.kek, dek)
	if err != nil {
		return "", "", fmt.Errorf("DEK wrapping failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(wrappedDEK),
		nil
}

// Decrypt decrypts an envelope-encrypted secret.
func (e *Engine) Decrypt(encryptedValue, encryptedDEK string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	wrappedDEK, err := base64.StdEncoding.DecodeString(encryptedDEK)
	if err != nil {
		return "", fmt.Errorf("invalid DEK encoding: %w", err)
	}

	// Unwrap DEK with KEK
	dek, err := aesGCMDecrypt(e.kek, wrappedDEK)
	if err != nil {
		return "", fmt.Errorf("DEK unwrapping failed: %w", err)
	}

	// Decrypt the value with the DEK
	plaintext, err := aesGCMDecrypt(dek, ciphertext)
	if err != nil {
		return "", fmt.Errorf("value decryption failed: %w", err)
	}

	// Zero out DEK immediately
	for i := range dek {
		dek[i] = 0
	}

	return string(plaintext), nil
}

// aesGCMEncrypt encrypts data with AES-256-GCM.
// Format: nonce (12 bytes) || ciphertext
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesGCMDecrypt decrypts AES-256-GCM data.
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HMACChain computes HMAC-SHA256 for audit log chain integrity.
func HMACChain(key []byte, eventID, prevHMAC, action, actorID, resourceID string, ts int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d", eventID, prevHMAC, action, actorID, resourceID, ts)))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateSecureToken generates a cryptographically secure random token.
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateKEK generates a new random 32-byte KEK and returns it as base64.
// Used for initial setup.
func GenerateKEK() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// HashToken hashes an API token for storage using SHA-256.
// We use SHA-256 here for quick lookup — bcrypt is used for passwords.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
