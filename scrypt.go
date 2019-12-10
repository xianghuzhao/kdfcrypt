package kdfcrypt

import (
	"golang.org/x/crypto/scrypt"
)

// Scrypt params.
type Scrypt struct {
	Cost            int `param:"N"`
	BlockSize       int `param:"r"`
	Parallelization int `param:"p"`
}

// SetDefaultParam sets the default param for scrypt
func (kdf *Scrypt) SetDefaultParam() {
	if kdf.Cost == 0 {
		kdf.Cost = 32768
	}
	if kdf.BlockSize == 0 {
		kdf.BlockSize = 8
	}
	if kdf.Parallelization == 0 {
		kdf.Parallelization = 1
	}
}

// Derive hash with scrypt.
func (kdf *Scrypt) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	hashed, err := scrypt.Key([]byte(password), salt, kdf.Cost, kdf.BlockSize, kdf.Parallelization, int(hashLength))
	return hashed, err
}
