package kdfcrypt

import (
	"testing"
)

var algorithms = map[string]KDF{
	"argon2i":  (*Argon2i)(nil),
	"argon2id": (*Argon2id)(nil),
	"scrypt":   (*Scrypt)(nil),
	"pbkdf2":   (*PBKDF2)(nil),
	"hkdf":     (*HKDF)(nil),
}

const pwEg = "This_is_1_Password_Example!"

var pwEgs = []string{
	pwEg,
	"",
	"                                ",
	"00000000000000000000000000000000",
	`,./;'[]\-='`,
	"!@#$%^&*()`~",
	`<>?:"{}|_+`,
}

var encodedStringData = []struct {
	encoded   string
	algorithm string
	param     string
	salt      string
	value     string
}{
	{
		encoded: "",
	},
	{
		encoded: "$",
	},
	{
		encoded: "$$",
	},
	{
		encoded: "aaabbbcccdddeee",
		value:   "aaabbbcccdddeee",
	},
	{
		encoded: "$$aaabbbcccdddeee$",
		value:   "aaabbbcccdddeee",
	},
	{
		encoded:   "$argon2id$v=19,i=1$qwert12345$jjjssslllaaauuuwww333",
		algorithm: "argon2id",
		param:     "v=19,i=1",
		salt:      "qwert12345",
		value:     "jjjssslllaaauuuwww333",
	},
	{
		encoded:   "$scrypt$wert12345$jjssslllaaauuuwww333",
		algorithm: "scrypt",
		salt:      "wert12345",
		value:     "jjssslllaaauuuwww333",
	},
	{
		encoded:   "$2a$14$HAhpTYrQ/1GIYvvcVFPm6e$qT4P7iPRHiEKm78rOvIPkNddd3Y6Dk2",
		algorithm: "2a",
		param:     "14",
		salt:      "HAhpTYrQ/1GIYvvcVFPm6e",
		value:     "qT4P7iPRHiEKm78rOvIPkNddd3Y6Dk2",
	},
	{
		encoded:   "$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
		algorithm: "6",
		salt:      "salt",
		value:     "IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
	},
}

func TestKDFName(t *testing.T) {
	for algorithm, kdf := range algorithms {
		name, err := KDFName(kdf)
		if err != nil {
			t.Errorf(`KDF name error for "%s": %s`, algorithm, err)
			continue
		}
		if name != algorithm {
			t.Errorf(`KDF name not correct for algorithm "%s": %s`, algorithm, name)
		}
	}
}

func TestParseCryptedString(t *testing.T) {
	for _, d := range encodedStringData {
		algorithm, param, salt, value := parseEncodedString(d.encoded)
		if algorithm != d.algorithm {
			t.Errorf("Parse algorithm unmatch: '%s' != '%s', (%s)", algorithm, d.algorithm, d.encoded)
		}
		if param != d.param {
			t.Errorf("Parse param unmatch: '%s' != '%s', (%s)", param, d.param, d.encoded)
		}
		if string(salt) != d.salt {
			t.Errorf("Parse salt unmatch: '%s' != '%s', (%s)", salt, d.salt, d.encoded)
		}
		if string(value) != d.value {
			t.Errorf("Parse value unmatch: '%s' != '%s', (%s)", value, d.value, d.encoded)
		}
	}
}

func TestEncodeAndVerify(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm:        algorithm,
			RandomSaltLength: 16,
		}

		for _, pw := range pwEgs {
			encoded, err := Encode(pw, opt)
			if err != nil {
				t.Fatalf("Encode error: %s", err)
			}

			match, err := Verify(pw, encoded)
			if err != nil {
				t.Fatalf("Verify error: %s", err)
			}
			if !match {
				t.Error("Verify does not match")
			}
		}
	}
}

func TestFixedSalt(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm: algorithm,
			Salt:      "A_fixed-salt+123",
		}
		encoded1, _ := Encode(pwEg, opt)
		encoded2, _ := Encode(pwEg, opt)
		if encoded1 != encoded2 {
			t.Errorf("Encoded key is not the same with fixed salt for algorithm: %s", algorithm)
		}
	}
}

func TestRandomSalt(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm:        algorithm,
			RandomSaltLength: 16,
		}
		encoded1, _ := Encode(pwEg, opt)
		encoded2, _ := Encode(pwEg, opt)
		if encoded1 == encoded2 {
			t.Errorf("Encoded key is the same with random salt for algorithm: %s", algorithm)
		}
	}
}
