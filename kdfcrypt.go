package kdfcrypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"reflect"
	"strings"
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

type kdf interface {
	GetSalt() []byte
	SetSalt(salt []byte)

	GenerateParam() (string, error)
	ParseParam(param string) error

	KDF(key []byte) ([]byte, error)
	Verify(key, hashed []byte) (bool, error)
}

var kdfs = []kdf{
	(*PBKDF2)(nil),
	(*Bcrypt)(nil),
}

var mapKDF map[string]reflect.Type

func init() {
	mapKDF = make(map[string]reflect.Type)
	for _, method := range kdfs {
		methodName := strings.ToLower(reflect.TypeOf(method).Elem().Name())
		mapKDF[methodName] = reflect.TypeOf(method)
	}
}

func parseCryptedString(crypted string) (string, string, string, string) {
	var method, param, salt, value string

	crypted = strings.TrimPrefix(crypted, "$")
	crypted = strings.TrimSuffix(crypted, "$")

	frags := strings.Split(crypted, "$")
	if len(frags) == 0 {
		return method, param, salt, value
	}
	value = frags[len(frags)-1]

	frags = frags[:len(frags)-1]
	if len(frags) == 0 {
		return method, param, salt, value
	}
	method = frags[0]

	frags = frags[1:]
	if len(frags) == 0 {
		return method, param, salt, value
	}
	salt = frags[len(frags)-1]

	frags = frags[:len(frags)-1]
	if len(frags) == 0 {
		return method, param, salt, value
	}
	param = frags[0]

	return method, param, salt, value
}

// ListAvailableKDFMethods list all the available kdf methods
func ListAvailableKDFMethods() []string {
	keys := make([]string, 0, len(mapKDF))
	for method := range mapKDF {
		keys = append(keys, method)
	}
	return keys
}

// Generate crypted key derivation
func Generate(key string, d kdf) (string, error) {
	method := strings.ToLower(reflect.TypeOf(d).Elem().Name())

	keyDerived, err := d.KDF([]byte(key))
	if err != nil {
		return "", err
	}

	value := base64.RawStdEncoding.EncodeToString(keyDerived)

	// Do this after d.KDF because salt may be generated there
	salt := base64.RawStdEncoding.EncodeToString(d.GetSalt())

	param, err := d.GenerateParam()
	if err != nil {
		return "", err
	}

	hashed := fmt.Sprintf("$%s$%s$%s$%s", method, param, salt, value)

	return hashed, nil
}

// Verify key and crypted
func Verify(key, crypted string) (bool, error) {
	method, param, salt, value := parseCryptedString(crypted)

	typeKDF, ok := mapKDF[method]
	if !ok {
		return false, fmt.Errorf("Method not available: '%s'", method)
	}

	d := reflect.New(typeKDF.Elem()).Interface().(kdf)

	saltOrigin, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}

	valueOrigin, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return false, err
	}

	d.ParseParam(param)
	d.SetSalt(saltOrigin)

	match, err := d.Verify([]byte(key), valueOrigin)
	if err != nil {
		return false, err
	}

	return match, nil
}
