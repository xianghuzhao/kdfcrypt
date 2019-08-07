package kdfcrypt

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters
type Argon2id struct {
	kdfCommon
	Iteration   uint32
	Parallelism uint8
	Memory      uint32
}

// GenerateParam get params from string
func (d *Argon2id) GenerateParam() (string, error) {
	param := fmt.Sprintf("v=%d,t=%d,m=%d,p=%d", argon2.Version, d.Iteration, d.Memory, d.Parallelism)
	return param, nil
}

// ParseParam get params from string
func (d *Argon2id) ParseParam(param string) error {
	chunks := strings.Split(param, ",")
	for _, chunk := range chunks {
		kv := strings.Split(chunk, "=")
		if len(kv) != 2 {
			return fmt.Errorf("Invalid chunk: '%s'", chunk)
		}

		switch kv[0] {
		case "v":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid version number: '%s'", kv[1])
			}
			if i != argon2.Version {
				return fmt.Errorf("Version number must be: '%d'", argon2.Version)
			}
			d.Iteration = uint32(i)
		case "t":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid iteration number: '%s'", kv[1])
			}
			d.Iteration = uint32(i)
		case "m":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid memory number: '%s'", kv[1])
			}
			d.Memory = uint32(i)
		case "p":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid parallelism number: '%s'", kv[1])
			}
			d.Parallelism = uint8(i)
		default:
			return fmt.Errorf("Invalid param: '%s'", kv[0])
		}
	}
	return nil
}

// KDF with Argon2id
func (d *Argon2id) KDF(key []byte) ([]byte, error) {
	if d.Salt == nil {
		d.generateRandomSalt()
	}

	if d.KeyLength == 0 {
		d.KeyLength = 32
	}

	hashed := argon2.IDKey([]byte(key), d.Salt, d.Iteration, d.Memory, d.Parallelism, d.KeyLength)
	return hashed, nil
}

// Verify compare password with hash
func (d *Argon2id) Verify(key, hashed []byte) (bool, error) {
	d.KeyLength = uint32(len(hashed))
	return verifyByKDF(key, hashed, d)
}
