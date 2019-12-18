package kdfcrypt

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2 base params.
type Argon2 struct {
	Version     uint8  `param:"v"`
	Memory      uint32 `param:"m"`
	Iteration   uint32 `param:"t"`
	Parallelism uint8  `param:"p"`
}

// Argon2i deals with argon2i KDF.
type Argon2i struct {
	Argon2
}

func (kdf *Argon2) validateVersion() error {
	if kdf.Version != argon2.Version {
		return fmt.Errorf(`Argon2 version "0x%x" not supported`, kdf.Version)
	}
	return nil
}

// SetDefaultParam sets the default param for argon2.
func (kdf *Argon2) SetDefaultParam() {
	if kdf.Version == 0 {
		kdf.Version = argon2.Version
	}
	if kdf.Iteration == 0 {
		kdf.Iteration = 1
	}
	if kdf.Memory == 0 {
		kdf.Memory = 64 * 1024
	}
	if kdf.Parallelism == 0 {
		kdf.Parallelism = 1
	}
}

// Derive hash with Argon2i.
func (kdf *Argon2i) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validateVersion(); err != nil {
		return nil, err
	}

	hashed := argon2.Key([]byte(password), salt, kdf.Iteration, kdf.Memory, kdf.Parallelism, hashLength)
	return hashed, nil
}

// Argon2id deals with argon2id KDF.
type Argon2id struct {
	Argon2
}

// Derive hash with Argon2id.
func (kdf *Argon2id) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validateVersion(); err != nil {
		return nil, err
	}

	hashed := argon2.IDKey([]byte(password), salt, kdf.Iteration, kdf.Memory, kdf.Parallelism, hashLength)
	return hashed, nil
}
