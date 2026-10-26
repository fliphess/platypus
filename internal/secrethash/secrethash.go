// Package secrethash hashes one-time secrets (bootstrap tokens and recovery
// codes) with argon2id, so the database never holds them in plain text.
package secrethash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters follow the OWASP recommendation for argon2id: 19 MiB of memory,
// two passes, one thread.
const (
	memoryKiB = 19 * 1024
	passes    = 2
	threads   = 1
	saltBytes = 16
	keyBytes  = 32
)

var encoding = base64.RawStdEncoding

// Hash returns an encoded argon2id hash of secret, including its salt and
// parameters, in the common $argon2id$v=19$m=...,t=...,p=...$salt$hash form.
func Hash(secret string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(secret), salt, passes, memoryKiB, threads, keyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, passes, threads, encoding.EncodeToString(salt), encoding.EncodeToString(key)), nil
}

// Verify reports whether secret matches an encoded hash from Hash. It takes
// the parameters from the encoded hash, so old hashes keep working when the
// defaults change.
func Verify(secret, encoded string) bool {
	params, salt, want, err := decode(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(secret), salt, params.passes, params.memoryKiB, params.threads, keyBytes)
	return subtle.ConstantTimeCompare(got, want) == 1
}

type parameters struct {
	memoryKiB uint32
	passes    uint32
	threads   uint8
}

func decode(encoded string) (parameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return parameters{}, nil, nil, errors.New("not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return parameters{}, nil, nil, errors.New("unsupported argon2 version")
	}
	var p parameters
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.passes, &p.threads); err != nil {
		return parameters{}, nil, nil, errors.New("bad argon2 parameters")
	}
	// The hash comes from the database, but a corrupt or imported row must
	// fail closed instead of panicking or asking for unbounded memory.
	if p.memoryKiB < 8 || p.memoryKiB > 1<<20 || p.passes < 1 || p.passes > 16 ||
		p.threads < 1 || p.threads > 64 || p.memoryKiB < 8*uint32(p.threads) {
		return parameters{}, nil, nil, errors.New("argon2 parameters out of range")
	}
	salt, err := encoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return parameters{}, nil, nil, errors.New("bad salt")
	}
	key, err := encoding.DecodeString(parts[5])
	if err != nil || len(key) != keyBytes {
		return parameters{}, nil, nil, errors.New("bad hash")
	}
	return p, salt, key, nil
}
