package kdfcrypt

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
)

type hashFunc func() hash.Hash

var hashFuncMap = map[string]hashFunc{
	"md5":        md5.New,
	"sha1":       sha1.New,
	"sha256":     sha256.New,
	"sha512":     sha512.New,
	"sha384":     sha512.New384,
	"sha512/224": sha512.New512_224,
	"sha512/256": sha512.New512_256,
}

type kdfCommon struct {
	Salt              []byte
	DefaultSaltLength uint32
	KeyLength         uint32
}

func (d *kdfCommon) GetSalt() []byte {
	return d.Salt
}

func (d *kdfCommon) SetSalt(salt []byte) {
	d.Salt = salt
}

func (d *kdfCommon) GetKeyLength() uint32 {
	return d.KeyLength
}

func (d *kdfCommon) SetKeyLength(length uint32) {
	d.KeyLength = length
}

func (d *kdfCommon) generateRandomSalt() {
	if d.DefaultSaltLength == 0 {
		d.DefaultSaltLength = 16
	}

	salt, err := generateRandomBytes(d.DefaultSaltLength)
	if err == nil {
		d.Salt = salt
	}
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func verifyByKDF(key, hashed []byte, d KDF) (bool, error) {
	keyDerived, err := d.KDF([]byte(key))
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeEq(int32(len(hashed)), int32(len(keyDerived))) == 0 {
		return false, nil
	}
	if subtle.ConstantTimeCompare(hashed, keyDerived) == 1 {
		return true, nil
	}
	return false, nil
}
