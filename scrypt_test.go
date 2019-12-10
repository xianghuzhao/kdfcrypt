package kdfcrypt

import (
	"encoding/hex"
	"testing"
)

var scryptEgs = []struct {
	cost            int
	blockSize       int
	parallelization int
	salt            string
	hashLength      uint32
	key             string
	scryptResult    string
}{
	{
		cost:            16384,
		blockSize:       8,
		parallelization: 1,
		salt:            "abcdefgh",
		hashLength:      32,
		key:             "This_is_1_Password_Example!",
		scryptResult:    "9638fb20584c46380657b4d305f73e2fbc21217da23f8394ff93a3fa290a0191",
	},
	{
		cost:            32768,
		blockSize:       16,
		parallelization: 3,
		salt:            "pIBFX2B05zuR7DSl",
		hashLength:      32,
		key:             "sdOrYO5wvpQXF8tAxNC7Jt",
		scryptResult:    "18f5d6505a6e96a3be3bc593f1b4665b48203732652c68d99a656fb336866d78",
	},
}

func TestScrypt(t *testing.T) {
	for _, scryptEg := range scryptEgs {
		kdf := &Scrypt{
			Cost:            scryptEg.cost,
			BlockSize:       scryptEg.blockSize,
			Parallelization: scryptEg.parallelization,
		}
		kdf.SetDefaultParam()
		hashed, err := kdf.Generate([]byte(scryptEg.key), []byte(scryptEg.salt), scryptEg.hashLength)
		if err != nil {
			t.Errorf("Scrypt generate error: %s", err)
		}
		hashedHex := hex.EncodeToString(hashed)
		if hashedHex != scryptEg.scryptResult {
			t.Errorf(`Scrypt get wrong result for "%s": %s | %s`, scryptEg.key, hashedHex, scryptEg.scryptResult)
		}
	}
}

func TestEncodeFromScrypt(t *testing.T) {
	kdf := &Scrypt{
		Cost:            32768,
		BlockSize:       8,
		Parallelization: 1,
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
