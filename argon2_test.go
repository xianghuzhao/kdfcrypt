package kdfcrypt

import (
	"encoding/hex"
	"testing"
)

var argon2Egs = []struct {
	iteration      uint32
	memory         uint32
	parallelism    uint8
	salt           string
	hashLength     uint32
	key            string
	argon2iResult  string
	argon2idResult string
}{
	{
		iteration:      1,
		memory:         8 * 1024,
		parallelism:    1,
		salt:           "abcdefgh",
		hashLength:     32,
		key:            "This_is_1_Password_Example!",
		argon2iResult:  "1eb637ad2907b72f2a9530f3a8e24b377ba2714fc1f30e761dc11297fbb871d7",
		argon2idResult: "c86aca231062bb7b0c03574d8655e30ddd152df7f94d7af9a083857178aa3650",
	},
	{
		iteration:      2,
		memory:         1024,
		parallelism:    3,
		salt:           "pIBFX2B05zuR7DSl",
		hashLength:     32,
		key:            "sdOrYO5wvpQXF8tAxNC7Jt",
		argon2iResult:  "c9492f7b9fb508a53e6ec75ea6a53ec6ce15d8d53b0d0e6bbe333caadc197540",
		argon2idResult: "7c27ee7675bd707d9320188ae7600080ec997d16cd818bfec8a8b7510add420d",
	},
}

func TestArgon2i(t *testing.T) {
	for _, argon2Eg := range argon2Egs {
		kdf := &Argon2i{
			Argon2: Argon2{
				Iteration:   argon2Eg.iteration,
				Memory:      argon2Eg.memory,
				Parallelism: argon2Eg.parallelism,
			},
		}
		kdf.SetDefaultParam()
		hashed, err := kdf.Derive([]byte(argon2Eg.key), []byte(argon2Eg.salt), argon2Eg.hashLength)
		if err != nil {
			t.Errorf("Argon2i generate error: %s", err)
		}
		hashedHex := hex.EncodeToString(hashed)
		if hashedHex != argon2Eg.argon2iResult {
			t.Errorf(`Argon2i get wrong result for "%s": %s | %s`, argon2Eg.key, hashedHex, argon2Eg.argon2iResult)
		}
	}
}

func TestArgon2id(t *testing.T) {
	for _, argon2Eg := range argon2Egs {
		kdf := &Argon2id{
			Argon2: Argon2{
				Iteration:   argon2Eg.iteration,
				Memory:      argon2Eg.memory,
				Parallelism: argon2Eg.parallelism,
			},
		}
		kdf.SetDefaultParam()
		hashed, err := kdf.Derive([]byte(argon2Eg.key), []byte(argon2Eg.salt), argon2Eg.hashLength)
		if err != nil {
			t.Errorf("Argon2id generate error: %s", err)
		}
		hashedHex := hex.EncodeToString(hashed)
		if hashedHex != argon2Eg.argon2idResult {
			t.Errorf(`Argon2id get wrong result for "%s": %s | %s`, argon2Eg.key, hashedHex, argon2Eg.argon2idResult)
		}
	}
}

func TestEncodeFromArgon2i(t *testing.T) {
	kdf := &Argon2i{
		Argon2: Argon2{
			Iteration:   1,
			Memory:      8 * 1024,
			Parallelism: 1,
		},
	}
	kdf.SetDefaultParam()

	encoded, err := EncodeFromKDF(keyEg, kdf, "A_fixed-salt+123", 32)
	if err != nil {
		t.Fatalf("Encode from KDF error: %s", err)
	}

	match, err := Verify(keyEg, encoded)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !match {
		t.Error("Verify does not match")
	}
}
