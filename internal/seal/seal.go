// Package seal encrypts small values with AES-256-GCM under the key from
// PLATYPUS_ENCRYPTION_KEY: TOTP secrets in the database and the short-lived
// login state cookie.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"platypus/internal/sensitive"
)

// Sealer encrypts and authenticates values.
type Sealer struct {
	aead  cipher.AEAD
	keyID string
}

// New creates a Sealer from a base64-encoded 32-byte key.
func New(encodedKey sensitive.Value) (*Sealer, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey.Reveal())
	if err != nil || len(key) != 32 {
		return nil, errors.New("the encryption key must be 32 bytes, base64-encoded")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	// The key ID identifies which key sealed a value, so the key can be
	// rotated later. It reveals nothing about the key itself.
	sum := sha256.Sum256(append([]byte("platypus key id:"), key...))
	return &Sealer{aead: aead, keyID: hex.EncodeToString(sum[:4])}, nil
}

// KeyID identifies the key in use.
func (s *Sealer) KeyID() string {
	return s.keyID
}

// Seal encrypts plaintext. context binds the ciphertext to its purpose and
// owner (for example a user id), so a sealed value can't be reused elsewhere.
func (s *Sealer) Seal(plaintext, context []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, context), nil
}

// Open decrypts a value from Seal.
func (s *Sealer) Open(ciphertext, context []byte, keyID string) ([]byte, error) {
	if keyID != s.keyID {
		return nil, fmt.Errorf("value was sealed with key %s, but the current key is %s", keyID, s.keyID)
	}
	if len(ciphertext) < s.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, sealed := ciphertext[:s.aead.NonceSize()], ciphertext[s.aead.NonceSize():]
	plaintext, err := s.aead.Open(nil, nonce, sealed, context)
	if err != nil {
		return nil, errors.New("could not decrypt: wrong key or tampered value")
	}
	return plaintext, nil
}
