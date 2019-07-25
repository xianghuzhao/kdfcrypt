package derivation

import (
	"testing"
)

func TestPBKDF2Derive(t *testing.T) {
	d := PBKDF2{
		KeyLength: 32,
		Iteration: 4096,
		HashFunc:  "md5",
	}

	key := "password"

	hashed, err := d.Derive([]byte(key))
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
