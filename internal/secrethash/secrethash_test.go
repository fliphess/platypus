package secrethash

import (
	"strings"
	"testing"
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
