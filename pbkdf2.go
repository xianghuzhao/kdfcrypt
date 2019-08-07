package kdfcrypt

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 parameters
type PBKDF2 struct {
	kdfCommon
	Iteration int
	HashFunc  string
}

// GenerateParam get params from string
func (d *PBKDF2) GenerateParam() (string, error) {
	param := fmt.Sprintf("iter=%d,hash=%s", d.Iteration, d.HashFunc)
	return param, nil
}

// ParseParam get params from string
func (d *PBKDF2) ParseParam(param string) error {
	chunks := strings.Split(param, ",")
	for _, chunk := range chunks {
		kv := strings.Split(chunk, "=")
		if len(kv) != 2 {
			return fmt.Errorf("Invalid chunk: '%s'", chunk)
		}

		switch kv[0] {
		case "iter":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid iter number: '%s'", kv[1])
			}
			d.Iteration = i
		case "hash":
			d.HashFunc = kv[1]
		default:
			return fmt.Errorf("Invalid param: '%s'", kv[0])
		}
	}
	return nil
}

// KDF with PBKDF2
func (d *PBKDF2) KDF(key []byte) ([]byte, error) {
	hashFunc, ok := hashFuncMap[d.HashFunc]
	if !ok {
		return nil, fmt.Errorf("Hash func not valid: %s", d.HashFunc)
	}

	if d.Salt == nil {
		d.generateRandomSalt()
	}

	hashed := pbkdf2.Key([]byte(key), d.Salt, d.Iteration, int(d.KeyLength), hashFunc)
	return hashed, nil
}

// Verify compare password with hash
func (d *PBKDF2) Verify(key, hashed []byte) (bool, error) {
	d.KeyLength = uint32(len(hashed))
	return verifyByKDF(key, hashed, d)
}
