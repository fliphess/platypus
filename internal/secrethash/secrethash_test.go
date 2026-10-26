package secrethash

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := Hash("correct horse")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("unexpected encoding: %s", hash)
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("hash contains the secret")
	}
	if !Verify("correct horse", hash) {
		t.Error("Verify rejects the right secret")
	}
	if Verify("wrong horse", hash) {
		t.Error("Verify accepts a wrong secret")
	}

	other, _ := Hash("correct horse")
	if other == hash {
		t.Error("two hashes of the same secret must differ (salt)")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, encoded := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=x$a$b"} {
		if Verify("anything", encoded) {
			t.Errorf("Verify accepted %q", encoded)
		}
	}
}

// A hash with syntactically valid but unsafe parameters fails closed instead
// of panicking or asking argon2 for unbounded resources.
func TestVerifyRejectsMalformedParameters(t *testing.T) {
	salt := encoding.EncodeToString(make([]byte, saltBytes))
	key := encoding.EncodeToString(make([]byte, keyBytes))
	for _, params := range []string{
		"m=0,t=1,p=1",
		"m=19456,t=0,p=1",
		"m=19456,t=1,p=0",
		"m=1048577,t=1,p=1",
		"m=19456,t=99,p=1",
	} {
		encoded := fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, params, salt, key)
		if Verify("secret", encoded) {
			t.Errorf("Verify accepted unsafe parameters %q", params)
		}
	}
	shortSalt := encoding.EncodeToString(make([]byte, 4))
	encoded := fmt.Sprintf("$argon2id$v=%d$m=19456,t=2,p=1$%s$%s", argon2.Version, shortSalt, key)
	if Verify("secret", encoded) {
		t.Error("Verify accepted a short salt")
	}
}
