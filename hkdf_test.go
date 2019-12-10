package kdfcrypt

import (
	"encoding/hex"
	"testing"
)

var hkdfEgs = []struct {
	hashFunc   string
	info       string
	salt       string
	hashLength uint32
	password   string
	hkdfResult string
}{
	{
		hashFunc:   "sha512",
		info:       "",
		salt:       "abcdefgh",
		hashLength: 32,
		password:   "This_is_1_Password_Example!",
		hkdfResult: "3a66ccc1d191b41535798dc5e4e4e65e0f2b592ecbcd579f7ebe0c2a0bc1e8bb",
	},
	{
		hashFunc:   "sha256",
		info:       "Just-info",
		salt:       "pIBFX2B05zuR7DSl",
		hashLength: 32,
		password:   "sdOrYO5wvpQXF8tAxNC7Jt",
		hkdfResult: "e1863ee8d038a2400de4fab6beb780d06853673ddf7d54f5d70b8f4b58f680a2",
	},
}

func TestHKDF(t *testing.T) {
	for _, hkdfEg := range hkdfEgs {
		kdf := &HKDF{
			HashFunc: hkdfEg.hashFunc,
			Info:     hkdfEg.info,
		}
		kdf.SetDefaultParam()
		hashed, err := kdf.Derive([]byte(hkdfEg.password), []byte(hkdfEg.salt), hkdfEg.hashLength)
		if err != nil {
			t.Errorf("HKDF generate error: %s", err)
		}
		hashedHex := hex.EncodeToString(hashed)
		if hashedHex != hkdfEg.hkdfResult {
			t.Errorf(`HKDF get wrong result for "%s": %s | %s`, hkdfEg.password, hashedHex, hkdfEg.hkdfResult)
		}
	}
}

func TestEncodeFromHKDF(t *testing.T) {
	kdf := &HKDF{
		HashFunc: "md5",
		Info:     "SomeInfo",
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
