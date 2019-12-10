package kdfcrypt

import (
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 params.
type PBKDF2 struct {
	Iteration uint32 `param:"iter"`
	HashFunc  string `param:"hash"`
}

// SetDefaultParam sets the default param for PBKDF2
func (kdf *PBKDF2) SetDefaultParam() {
	if kdf.Iteration == 0 {
		kdf.Iteration = 1024
	}
	if kdf.HashFunc == "" {
		kdf.HashFunc = "sha512"
	}
}

// Derive hash with PBKDF2.
func (kdf *PBKDF2) Derive(key, salt []byte, hashLength uint32) ([]byte, error) {
	hashFunc, ok := hashFuncMap[kdf.HashFunc]
	if !ok {
		return nil, fmt.Errorf("Hash func for PBKDF2 is not valid: %s", kdf.HashFunc)
	}

	hashed := pbkdf2.Key([]byte(key), salt, int(kdf.Iteration), int(hashLength), hashFunc)
	return hashed, nil
}
