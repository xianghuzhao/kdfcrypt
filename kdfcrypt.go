package kdfcrypt

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
)

// KDF should be implemented for different kdfs
type KDF interface {
	GetSalt() []byte
	SetSalt(salt []byte)

	GetKeyLength() uint32
	SetKeyLength(length uint32)

	GenerateParam() (string, error)
	ParseParam(param string) error

	KDF(key []byte) ([]byte, error)
	Verify(key, hashed []byte) (bool, error)
}

var kdfs = []KDF{
	(*Argon2id)(nil),
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

// CreateKDF crypted key derivation
func CreateKDF(method, param string) (KDF, error) {
	typeKDF, ok := mapKDF[method]
	if !ok {
		return nil, fmt.Errorf("Method not available: '%s'", method)
	}

	d := reflect.New(typeKDF.Elem()).Interface().(KDF)

	err := d.ParseParam(param)
	if err != nil {
		return nil, err
	}

	return d, nil
}

// Generate crypted key derivation
func Generate(key string, d KDF) (string, error) {
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

	d, err := CreateKDF(method, param)
	if err != nil {
		return false, err
	}

	saltOrigin, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}

	valueOrigin, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return false, err
	}

	d.SetSalt(saltOrigin)

	match, err := d.Verify([]byte(key), valueOrigin)
	if err != nil {
		return false, err
	}

	return match, nil
}
