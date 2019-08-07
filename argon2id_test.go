package kdfcrypt

import (
	"testing"
)

func TestArgon2idKDF(t *testing.T) {
	d := Argon2id{
		Iteration: 2,
		Memory:    32 * 1024,
		Thread:    1,
	}
	d.KeyLength = 32

	key := "password"

	hashed, err := d.KDF([]byte(key))
	if err != nil {
		t.Fatalf("Fatal error when derive: %s", err)
	}

	match, err := d.Verify([]byte(key), hashed)
	if err != nil {
		t.Fatalf("Fatal error when verify: %s", err)
	}
	if !match {
		t.Errorf("Password does not match: %s", err)
	}
}
