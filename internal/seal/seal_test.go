package seal

import (
	"strings"
	"testing"

	"platypus/internal/config"
	"platypus/internal/sensitive"
)

func TestSealer(t *testing.T) {
	sealer, err := New(sensitive.New(config.TestEncryptionKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	sealed, err := sealer.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user:1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(string(sealed), "JBSWY3DPEHPK3PXP") {
		t.Fatal("ciphertext contains the plaintext")
	}

	opened, err := sealer.Open(sealed, []byte("user:1"), sealer.KeyID())
	if err != nil || string(opened) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Open = %q, %v", opened, err)
	}
	if _, err := sealer.Open(sealed, []byte("user:2"), sealer.KeyID()); err == nil {
		t.Error("a value sealed for user 1 must not open for user 2")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := sealer.Open(sealed, []byte("user:1"), sealer.KeyID()); err == nil {
		t.Error("a tampered value must not open")
	}
	if _, err := New(sensitive.New("c2hvcnQ=")); err == nil {
		t.Error("a short key must be refused")
	}
}
