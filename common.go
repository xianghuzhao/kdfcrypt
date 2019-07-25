package derivation

import (
	"crypto/rand"
	"crypto/subtle"
)

type deriverCommon struct {
	Salt              []byte
	DefaultSaltLength uint32
}

func (d *deriverCommon) GetSalt() []byte {
	return d.Salt
}

func (d *deriverCommon) SetSalt(salt []byte) {
	d.Salt = salt
}

func (d *deriverCommon) generateRandomSalt() {
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

func verifyByDerive(key, hashed []byte, d deriver) (bool, error) {
	keyDerived, err := d.Derive([]byte(key))
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
