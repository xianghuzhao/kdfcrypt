package kdfcrypt

import (
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 contains PBKDF2 parameters.
type PBKDF2 struct {
	Iteration uint32 `param:"iter"`
	HashFunc  string `param:"hash"`
}

// SetDefaultParam sets the default PBKDF2 parameters.
func (kdf *PBKDF2) SetDefaultParam() {
	if kdf.Iteration == 0 {
		kdf.Iteration = 600_000
	}
	if kdf.HashFunc == "" {
		kdf.HashFunc = "sha256"
	}
}

func (kdf *PBKDF2) validate() error {
	if kdf.Iteration == 0 {
		return fmt.Errorf("%w: PBKDF2 iterations must be greater than zero", ErrInvalidParameter)
	}
	if _, ok := hashFuncMap[kdf.HashFunc]; !ok {
		return fmt.Errorf("%w: hash function for PBKDF2 is not valid: %s", ErrInvalidParameter, kdf.HashFunc)
	}
	return nil
}

// Derive derives a key with PBKDF2.
func (kdf *PBKDF2) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if hashLength == 0 || uint64(hashLength) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: hash length is invalid", ErrInvalidParameter)
	}
	if uint64(kdf.Iteration) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: PBKDF2 iteration count is too large", ErrInvalidParameter)
	}
	hashFunc, ok := hashFuncMap[kdf.HashFunc]
	if !ok {
		return nil, fmt.Errorf("%w: hash function for PBKDF2 is not valid: %s", ErrInvalidParameter, kdf.HashFunc)
	}

	hashed := pbkdf2.Key([]byte(password), salt, int(kdf.Iteration), int(hashLength), hashFunc)
	return hashed, nil
}
