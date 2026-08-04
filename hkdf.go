package kdfcrypt

import (
	"crypto/hkdf"
	"fmt"
)

// HKDF contains HKDF parameters.
type HKDF struct {
	HashFunc string `param:"hash"`
	Info     string `param:"info"`
}

func (kdf *HKDF) validate() error {
	if _, ok := hashFuncMap[kdf.HashFunc]; !ok {
		return fmt.Errorf("%w: hash function for HKDF is not valid: %s", ErrInvalidParameter, kdf.HashFunc)
	}
	return nil
}

// SetDefaultParam sets the default HKDF parameters.
func (kdf *HKDF) SetDefaultParam() {
	if kdf.HashFunc == "" {
		kdf.HashFunc = "sha512"
	}
}

// Derive derives a key with HKDF.
func (kdf *HKDF) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if hashLength == 0 || uint64(hashLength) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: hash length is invalid", ErrInvalidParameter)
	}
	hashFunc, ok := hashFuncMap[kdf.HashFunc]
	if !ok {
		return nil, fmt.Errorf("%w: hash function for HKDF is not valid: %s", ErrInvalidParameter, kdf.HashFunc)
	}
	if uint64(hashLength) > uint64(hashFunc().Size()*255) {
		return nil, fmt.Errorf("%w: HKDF hash length is too large", ErrInvalidParameter)
	}
	hashed, err := hkdf.Key(hashFunc, []byte(password), salt, kdf.Info, int(hashLength))
	if err != nil {
		return nil, fmt.Errorf("derive HKDF key: %w", err)
	}
	return hashed, nil
}
