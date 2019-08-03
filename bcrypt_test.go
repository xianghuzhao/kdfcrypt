package kdfcrypt

import (
	"testing"
)

func TestBcryptDerive(t *testing.T) {
	b := Bcrypt{
		Cost: 10,
	}

	key := "password"

	hashed, err := b.KDF([]byte(key))
	if err != nil {
		t.Fatalf("Fatal error when derive: %s", err)
	}

	match, err := b.Verify([]byte(key), hashed)
	if err != nil {
		t.Fatalf("Fatal error when verify: %s", err)
	}
	if !match {
		t.Errorf("Password does not match: %s", err)
	}
}
