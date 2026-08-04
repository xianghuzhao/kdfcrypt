package kdfcrypt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
)

var algorithms = map[string]KDF{
	"argon2i":  (*Argon2i)(nil),
	"argon2id": (*Argon2id)(nil),
	"scrypt":   (*Scrypt)(nil),
	"pbkdf2":   (*PBKDF2)(nil),
	"hkdf":     (*HKDF)(nil),
}

var testParams = map[string]string{
	"argon2i":  "v=19,m=8192,t=1,p=1",
	"argon2id": "v=19,m=8192,t=1,p=1",
	"scrypt":   "N=16384,r=8,p=1",
	"pbkdf2":   "iter=1024,hash=sha512",
	"hkdf":     "hash=sha512,info=",
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

func TestKDFName(t *testing.T) {
	for algorithm, kdf := range algorithms {
		name, err := KDFName(kdf)
		if err != nil {
			t.Errorf("KDFName(%s): %v", algorithm, err)
			continue
		}
		if name != algorithm {
			t.Errorf("KDFName(%s) = %s", algorithm, name)
		}
	}
}

func TestParseEncodedString(t *testing.T) {
	encoded := "$argon2id$v=19,m=19456,t=2,p=1$c2FsdA$aGFzaA"
	got, err := parseEncodedString(encoded)
	if err != nil {
		t.Fatalf("parse encoded string: %v", err)
	}
	want := encodedPassword{
		algorithm: "argon2id",
		param:     "v=19,m=19456,t=2,p=1",
		salt:      "c2FsdA",
		hash:      "aGFzaA",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parse encoded string = %#v, want %#v", got, want)
	}

	invalid := []string{
		"",
		"$",
		"$$",
		"argon2id$params$salt$hash",
		"$argon2id$params$salt$hash$",
		"$$params$salt$hash",
		"$argon2id$params$salt$",
	}
	for _, value := range invalid {
		if _, err := parseEncodedString(value); !errors.Is(err, ErrInvalidEncoding) {
			t.Errorf("parseEncodedString(%q) error = %v, want ErrInvalidEncoding", value, err)
		}
	}
}

func TestEncodeAndVerify(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm:        algorithm,
			Param:            testParams[algorithm],
			RandomSaltLength: 16,
		}

		for _, password := range pwEgs {
			encoded, err := Encode(password, opt)
			if err != nil {
				t.Fatalf("Encode(%s): %v", algorithm, err)
			}

			match, err := Verify(password, encoded)
			if err != nil {
				t.Fatalf("Verify(%s): %v", algorithm, err)
			}
			if !match {
				t.Errorf("Verify(%s) did not match", algorithm)
			}
		}
	}
}

func TestFixedSalt(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm: algorithm,
			Param:     testParams[algorithm],
			Salt:      "A_fixed-salt+123",
		}
		encoded1, err := Encode(pwEg, opt)
		if err != nil {
			t.Fatalf("Encode(%s): %v", algorithm, err)
		}
		encoded2, err := Encode(pwEg, opt)
		if err != nil {
			t.Fatalf("Encode(%s): %v", algorithm, err)
		}
		if encoded1 != encoded2 {
			t.Errorf("fixed-salt encodings differ for %s", algorithm)
		}
	}
}

func TestRandomSalt(t *testing.T) {
	for algorithm := range algorithms {
		opt := &Option{
			Algorithm:        algorithm,
			Param:            testParams[algorithm],
			RandomSaltLength: 16,
		}
		encoded1, err := Encode(pwEg, opt)
		if err != nil {
			t.Fatalf("Encode(%s): %v", algorithm, err)
		}
		encoded2, err := Encode(pwEg, opt)
		if err != nil {
			t.Fatalf("Encode(%s): %v", algorithm, err)
		}
		if encoded1 == encoded2 {
			t.Errorf("random-salt encodings match for %s", algorithm)
		}
	}
}

func TestEncodeDefaultsToRandomSalt(t *testing.T) {
	encoded, err := Encode(pwEg, &Option{Algorithm: "pbkdf2", Param: testParams["pbkdf2"]})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := parseEncodedString(encoded)
	if err != nil {
		t.Fatalf("parse encoded string: %v", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parsed.salt)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("default salt length = %d, want 16", len(salt))
	}
	hash, err := base64.RawStdEncoding.DecodeString(parsed.hash)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("default hash length = %d, want 32", len(hash))
	}
}

func TestDefaultParams(t *testing.T) {
	tests := []struct {
		algorithm string
		want      KDF
	}{
		{"argon2i", &Argon2i{Argon2{Version: 19, Memory: 64 * 1024, Iteration: 1, Parallelism: 1}}},
		{"argon2id", &Argon2id{Argon2{Version: 19, Memory: 19 * 1024, Iteration: 2, Parallelism: 1}}},
		{"scrypt", &Scrypt{Cost: 1 << 17, BlockSize: 8, Parallelization: 1}},
		{"pbkdf2", &PBKDF2{Iteration: 600_000, HashFunc: "sha256"}},
		{"hkdf", &HKDF{HashFunc: "sha512"}},
	}
	for _, test := range tests {
		got, err := CreateKDF(test.algorithm, "")
		if err != nil {
			t.Fatalf("CreateKDF(%s): %v", test.algorithm, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("CreateKDF(%s) = %#v, want %#v", test.algorithm, got, test.want)
		}
	}
}

func TestVerifyHistoricalEncodings(t *testing.T) {
	encodings := []string{
		"$argon2i$v=19,m=8192,t=1,p=1$YWJjZGVmZ2g$HrY3rSkHty8qlTDzqOJLN3uicU/B8w52HcESl/u4cdc",
		"$argon2id$v=19,m=8192,t=1,p=1$YWJjZGVmZ2g$yGrKIxBiu3sMA1dNhlXjDd0VLff5TXr5oIOFcXiqNlA",
		"$scrypt$N=16384,r=8,p=1$YWJjZGVmZ2g$ljj7IFhMRjgGV7TTBfc+L7whIX2iP4OU/5Oj+ikKAZE",
		"$pbkdf2$iter=1024,hash=sha512$YWJjZGVmZ2g$xOMjRqfRyOqv39SlLyqGMHX11XTCpy2ctjbLoXX8Aug",
		"$hkdf$hash=sha512,info=$YWJjZGVmZ2g$OmbMwdGRtBU1eY3F5OTmXg8rWS7LzVeffr4MKgvB6Ls",
	}
	for _, encoded := range encodings {
		match, err := Verify(pwEg, encoded)
		if err != nil {
			t.Errorf("Verify historical encoding: %v", err)
			continue
		}
		if !match {
			t.Errorf("historical encoding did not match: %s", encoded)
		}
	}
}

func TestEncodeFromKDFAllowsEmptySalt(t *testing.T) {
	kdf, err := CreateKDF("pbkdf2", testParams["pbkdf2"])
	if err != nil {
		t.Fatalf("CreateKDF: %v", err)
	}
	encoded, err := EncodeFromKDF(pwEg, kdf, "", 32)
	if err != nil {
		t.Fatalf("EncodeFromKDF: %v", err)
	}
	match, err := Verify(pwEg, encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !match {
		t.Fatal("empty-salt encoding did not match")
	}
}

func TestErrors(t *testing.T) {
	if _, err := Encode(pwEg, nil); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("Encode(nil) error = %v, want ErrInvalidParameter", err)
	}
	if _, err := Encode(pwEg, &Option{}); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("Encode(empty option) error = %v, want ErrInvalidParameter", err)
	}
	if _, err := CreateKDF("unknown", ""); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("CreateKDF(unknown) error = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := EncodeFromKDF(pwEg, (*PBKDF2)(nil), "", 32); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("EncodeFromKDF(nil) error = %v, want ErrInvalidParameter", err)
	}
	if _, err := CreateKDF("hkdf", "hash=sha512,info=bad$value"); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("CreateKDF(reserved info) error = %v, want ErrInvalidParameter", err)
	}

	invalidParams := []string{
		"iter=1024,hash=sha512,unknown=x",
		"iter=1024,iter=2048,hash=sha512",
		"iter=,hash=sha512",
		"iter=0,hash=sha512",
		"iter=999999999999999999999999,hash=sha512",
	}
	for _, param := range invalidParams {
		if _, err := CreateKDF("pbkdf2", param); !errors.Is(err, ErrInvalidParameter) {
			t.Errorf("CreateKDF(%q) error = %v, want ErrInvalidParameter", param, err)
		}
	}

	validParam := testParams["pbkdf2"]
	invalidEncodings := []struct {
		encoded string
		want    error
	}{
		{"$pbkdf2$" + validParam + "$%%%$aGFzaA", ErrInvalidEncoding},
		{"$pbkdf2$" + validParam + "$c2FsdA$%%%", ErrInvalidEncoding},
		{"$pbkdf2$iter=1024$c2FsdA$aGFzaA", ErrInvalidParameter},
		{"$pbkdf2$iter=1024,hash=sha512,hash=sha256$c2FsdA$aGFzaA", ErrInvalidParameter},
		{"$unknown$$c2FsdA$aGFzaA", ErrUnsupportedAlgorithm},
	}
	for _, test := range invalidEncodings {
		if _, err := Verify(pwEg, test.encoded); !errors.Is(err, test.want) {
			t.Errorf("Verify(%q) error = %v, want %v", test.encoded, err, test.want)
		}
	}
}

func TestDeriveRejectsInvalidParams(t *testing.T) {
	tests := []KDF{
		&Argon2id{Argon2: Argon2{Version: 19, Memory: 1024, Parallelism: 1}},
		&Scrypt{Cost: 3, BlockSize: 8, Parallelization: 1},
		&PBKDF2{HashFunc: "sha256"},
		&HKDF{HashFunc: "unknown"},
	}
	for _, kdf := range tests {
		if _, err := kdf.Derive([]byte("password"), []byte("salt"), 32); !errors.Is(err, ErrInvalidParameter) {
			t.Errorf("%T.Derive error = %v, want ErrInvalidParameter", kdf, err)
		}
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	encoded, err := Encode(pwEg, &Option{Algorithm: "pbkdf2", Param: testParams["pbkdf2"]})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	match, err := Verify("wrong", encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if match {
		t.Fatal("wrong password matched")
	}
}

func TestListKDFAlgorithmsSorted(t *testing.T) {
	got := ListKDFAlgorithms()
	if !slices.IsSorted(got) {
		t.Fatalf("ListKDFAlgorithms() = %v, want sorted values", got)
	}
}

func TestConcurrentRegistration(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("test-pbkdf2-%02d", i)
			RegisterKDF(name, (*PBKDF2)(nil))
			if _, err := CreateKDF(name, testParams["pbkdf2"]); err != nil {
				t.Errorf("CreateKDF(%s): %v", name, err)
			}
		}()
	}
	wg.Wait()
}
