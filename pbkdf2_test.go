package kdfcrypt

import (
	"encoding/hex"
	"testing"
)

var pbkdf2Egs = []struct {
	iteration    uint32
	hashFunc     string
	salt         string
	hashLength   uint32
	password     string
	pbkdf2Result string
}{
	{
		iteration:    1024,
		hashFunc:     "sha512",
		salt:         "abcdefgh",
		hashLength:   32,
		password:     "This_is_1_Password_Example!",
		pbkdf2Result: "c4e32346a7d1c8eaafdfd4a52f2a863075f5d574c2a72d9cb636cba175fc02e8",
	},
	{
		iteration:    2048,
		hashFunc:     "sha256",
		salt:         "pIBFX2B05zuR7DSl",
		hashLength:   32,
		password:     "sdOrYO5wvpQXF8tAxNC7Jt",
		pbkdf2Result: "946838e7646e24f1b7eca3dd6790e2f461772890797b0767948941420209c89b",
	},
}

func TestPBKDF2(t *testing.T) {
	for _, pbkdf2Eg := range pbkdf2Egs {
		kdf := &PBKDF2{
			Iteration: pbkdf2Eg.iteration,
			HashFunc:  pbkdf2Eg.hashFunc,
		}
		kdf.SetDefaultParam()
		hashed, err := kdf.Derive([]byte(pbkdf2Eg.password), []byte(pbkdf2Eg.salt), pbkdf2Eg.hashLength)
		if err != nil {
			t.Errorf("PBKDF2 generate error: %s", err)
		}
		hashedHex := hex.EncodeToString(hashed)
		if hashedHex != pbkdf2Eg.pbkdf2Result {
			t.Errorf(`PBKDF2 get wrong result for "%s": %s | %s`, pbkdf2Eg.password, hashedHex, pbkdf2Eg.pbkdf2Result)
		}
	}
}

func TestEncodeFromPBKDF2(t *testing.T) {
	kdf := &PBKDF2{
		Iteration: 1024,
		HashFunc:  "md5",
	}
	kdf.SetDefaultParam()

	encoded, err := EncodeFromKDF(pwEg, kdf, "A_fixed-salt+123", 32)
	if err != nil {
		t.Fatalf("Encode from KDF error: %s", err)
	}

	match, err := Verify(pwEg, encoded)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !match {
		t.Error("Verify does not match")
	}
}
