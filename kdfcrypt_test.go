package kdfcrypt

import (
	"fmt"
	"testing"
)

var cryptedStringData = []struct {
	str    string
	method string
	param  string
	salt   string
	value  string
}{
	{
		str: "",
	},
	{
		str: "$",
	},
	{
		str: "$$",
	},
	{
		str:   "aaabbbcccdddeee",
		value: "aaabbbcccdddeee",
	},
	{
		str:   "$$aaabbbcccdddeee$",
		value: "aaabbbcccdddeee",
	},
	{
		str:    "$argon2id$v=19,i=1$qwert12345$jjjssslllaaauuuwww333",
		method: "argon2id",
		param:  "v=19,i=1",
		salt:   "qwert12345",
		value:  "jjjssslllaaauuuwww333",
	},
	{
		str:    "$scrypt$wert12345$jjssslllaaauuuwww333",
		method: "scrypt",
		salt:   "wert12345",
		value:  "jjssslllaaauuuwww333",
	},
	{
		str:    "$2a$14$HAhpTYrQ/1GIYvvcVFPm6e$qT4P7iPRHiEKm78rOvIPkNddd3Y6Dk2",
		method: "2a",
		param:  "14",
		salt:   "HAhpTYrQ/1GIYvvcVFPm6e",
		value:  "qT4P7iPRHiEKm78rOvIPkNddd3Y6Dk2",
	},
	{
		str:    "$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
		method: "6",
		salt:   "salt",
		value:  "IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
	},
}

func TestParseCryptedString(t *testing.T) {
	for _, d := range cryptedStringData {
		method, param, salt, value := parseCryptedString(d.str)
		if method != d.method {
			t.Errorf("Parse method unmatch: '%s' != '%s', (%s)", method, d.method, d.str)
		}
		if param != d.param {
			t.Errorf("Parse param unmatch: '%s' != '%s', (%s)", param, d.param, d.str)
		}
		if string(salt) != d.salt {
			t.Errorf("Parse salt unmatch: '%s' != '%s', (%s)", salt, d.salt, d.str)
		}
		if string(value) != d.value {
			t.Errorf("Parse value unmatch: '%s' != '%s', (%s)", value, d.value, d.str)
		}
	}
}

func TestGenerateAndVerify(t *testing.T) {
	d := PBKDF2{
		Iteration: 4096,
		HashFunc:  "sha512/256",
	}
	d.KeyLength = 32

	key := "password"

	crypted, err := Generate(key, &d)
	if err != nil {
		t.Fatalf("Generate error: %s", err)
	}

	fmt.Println(crypted)

	match, err := Verify(key, crypted)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !match {
		t.Errorf("Verify does not match")
	}
}

func TestCreateKDF(t *testing.T) {
	kdf, err := CreateKDF("argon2id", "v=19,t=1,m=32768,p=1")
	if err != nil {
		t.Fatalf("Create KDF error: %s", err)
	}

	key := "password"

	crypted, err := Generate(key, kdf)
	if err != nil {
		t.Fatalf("Generate error: %s", err)
	}

	fmt.Println(crypted)

	match, err := Verify(key, crypted)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !match {
		t.Errorf("Verify does not match")
	}
}
