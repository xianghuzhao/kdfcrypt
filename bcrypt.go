package kdfcrypt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet)

const (
	encodedSaltSize = 22
	encodedHashSize = 31
)

func base64Encode(src []byte) []byte {
	n := bcEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	bcEncoding.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// Bcrypt parameters
type Bcrypt struct {
	Salt    []byte
	Cost    int
	Version string
}

// GetSalt get salt value
func (d *Bcrypt) GetSalt() []byte {
	return d.Salt
}

// SetSalt set salt value
func (d *Bcrypt) SetSalt(salt []byte) {
	d.Salt = salt
}

// GenerateParam get params from string
func (d *Bcrypt) GenerateParam() (string, error) {
	param := fmt.Sprintf("ver=%s,cost=%d", d.Version, d.Cost)
	return param, nil
}

// ParseParam get params from string
func (d *Bcrypt) ParseParam(param string) error {
	chunks := strings.Split(param, ",")
	for _, chunk := range chunks {
		kv := strings.Split(chunk, "=")
		if len(kv) != 2 {
			return fmt.Errorf("Invalid chunk: '%s'", chunk)
		}

		switch kv[0] {
		case "cost":
			i, err := strconv.Atoi(kv[1])
			if err != nil {
				return fmt.Errorf("Invalid cost number: '%s'", kv[1])
			}
			d.Cost = i
		case "version":
			d.Version = kv[1]
		default:
			return fmt.Errorf("Invalid param: '%s'", kv[0])
		}
	}
	return nil
}

// KDF get the kdf with bcrypt
func (d *Bcrypt) KDF(value []byte) ([]byte, error) {
	if d.Salt != nil {
		return nil, errors.New("Bcrypt does not support user defined salt")
	}

	if d.Cost == 0 {
		d.Cost = bcrypt.DefaultCost
	}

	result, err := bcrypt.GenerateFromPassword([]byte(value), d.Cost)
	if err != nil {
		return nil, err
	}

	resultStr := string(result)

	// Get the version
	versionStartIndex := 0
	if result[0] == '$' {
		versionStartIndex = 1
	}
	tempIndex := strings.Index(resultStr[versionStartIndex:], "$")
	if tempIndex < 0 {
		return nil, fmt.Errorf("Invalid result format from bcrypt: %s", resultStr)
	}
	version := resultStr[versionStartIndex : tempIndex+versionStartIndex]
	d.Version = version

	// Get the salt and hash
	saltIndex := strings.LastIndex(resultStr, "$")
	if saltIndex < 0 {
		return nil, fmt.Errorf("Invalid result format from bcrypt: %s", resultStr)
	}

	saltAndHash := result[saltIndex+1:]

	if len(saltAndHash) != encodedSaltSize+encodedHashSize {
		return nil, fmt.Errorf("Invalid result length from bcrypt: %s", resultStr)
	}

	salt64 := make([]byte, encodedSaltSize)
	hash64 := make([]byte, encodedHashSize)
	copy(salt64, saltAndHash[:encodedSaltSize])
	copy(hash64, saltAndHash[encodedSaltSize:])

	salt, err := base64Decode(salt64)
	if err != nil {
		return nil, fmt.Errorf("Invalid salt base64 code from bcrypt: %s", salt64)
	}
	d.Salt = salt

	hash, err := base64Decode(hash64)
	if err != nil {
		return nil, fmt.Errorf("Invalid hash base64 code from bcrypt: %s", hash64)
	}

	return hash, nil
}

// Verify compare password with hash
func (d *Bcrypt) Verify(key, hashed []byte) (bool, error) {
	salt64 := base64Encode(d.Salt)
	hash64 := base64Encode(hashed)

	crypted := fmt.Sprintf("$%s$%02d$%s%s", d.Version, d.Cost, salt64, hash64)

	err := bcrypt.CompareHashAndPassword([]byte(crypted), key)

	return err == nil, err
}
