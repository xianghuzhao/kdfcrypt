package kdfcrypt

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// Scrypt contains scrypt parameters.
type Scrypt struct {
	Cost            int `param:"N"`
	BlockSize       int `param:"r"`
	Parallelization int `param:"p"`
}

// SetDefaultParam sets the default scrypt parameters.
func (kdf *Scrypt) SetDefaultParam() {
	if kdf.Cost == 0 {
		kdf.Cost = 1 << 17
	}
	if kdf.BlockSize == 0 {
		kdf.BlockSize = 8
	}
	if kdf.Parallelization == 0 {
		kdf.Parallelization = 1
	}
}

func (kdf *Scrypt) validate() error {
	if kdf.Cost <= 1 || kdf.Cost&(kdf.Cost-1) != 0 {
		return fmt.Errorf("%w: scrypt N must be greater than 1 and a power of 2", ErrInvalidParameter)
	}
	if kdf.BlockSize <= 0 {
		return fmt.Errorf("%w: scrypt r must be greater than zero", ErrInvalidParameter)
	}
	if kdf.Parallelization <= 0 {
		return fmt.Errorf("%w: scrypt p must be greater than zero", ErrInvalidParameter)
	}
	if uint64(kdf.BlockSize)*uint64(kdf.Parallelization) >= 1<<30 {
		return fmt.Errorf("%w: scrypt parameters are too large", ErrInvalidParameter)
	}
	return nil
}

// Derive derives a key with scrypt.
func (kdf *Scrypt) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if hashLength == 0 || uint64(hashLength) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: hash length is invalid", ErrInvalidParameter)
	}
	hashed, err := scrypt.Key([]byte(password), salt, kdf.Cost, kdf.BlockSize, kdf.Parallelization, int(hashLength))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidParameter, err)
	}
	return hashed, nil
}
