package kdfcrypt

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2 contains parameters shared by Argon2 variants.
type Argon2 struct {
	Version     uint8  `param:"v"`
	Memory      uint32 `param:"m"`
	Iteration   uint32 `param:"t"`
	Parallelism uint8  `param:"p"`
}

// Argon2i implements the Argon2i KDF.
type Argon2i struct {
	Argon2
}

func (kdf *Argon2) validateVersion() error {
	if kdf.Version != argon2.Version {
		return fmt.Errorf("%w: argon2 version 0x%x is not supported", ErrInvalidParameter, kdf.Version)
	}
	return nil
}

func (kdf *Argon2) validate() error {
	if err := kdf.validateVersion(); err != nil {
		return err
	}
	if kdf.Iteration == 0 {
		return fmt.Errorf("%w: argon2 iterations must be greater than zero", ErrInvalidParameter)
	}
	if kdf.Memory == 0 {
		return fmt.Errorf("%w: argon2 memory must be greater than zero", ErrInvalidParameter)
	}
	if kdf.Parallelism == 0 {
		return fmt.Errorf("%w: argon2 parallelism must be greater than zero", ErrInvalidParameter)
	}
	return nil
}

// SetDefaultParam sets the default parameters for Argon2i.
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

// Derive derives a key with Argon2i.
func (kdf *Argon2i) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if hashLength == 0 {
		return nil, fmt.Errorf("%w: hash length must be greater than zero", ErrInvalidParameter)
	}

	hashed := argon2.Key([]byte(password), salt, kdf.Iteration, kdf.Memory, kdf.Parallelism, hashLength)
	return hashed, nil
}

// Argon2id implements the Argon2id KDF.
type Argon2id struct {
	Argon2
}

// SetDefaultParam sets the default parameters for Argon2id.
func (kdf *Argon2id) SetDefaultParam() {
	if kdf.Version == 0 {
		kdf.Version = argon2.Version
	}
	if kdf.Iteration == 0 {
		kdf.Iteration = 2
	}
	if kdf.Memory == 0 {
		kdf.Memory = 19 * 1024
	}
	if kdf.Parallelism == 0 {
		kdf.Parallelism = 1
	}
}

// Derive derives a key with Argon2id.
func (kdf *Argon2id) Derive(password, salt []byte, hashLength uint32) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if hashLength == 0 {
		return nil, fmt.Errorf("%w: hash length must be greater than zero", ErrInvalidParameter)
	}

	hashed := argon2.IDKey([]byte(password), salt, kdf.Iteration, kdf.Memory, kdf.Parallelism, hashLength)
	return hashed, nil
}
