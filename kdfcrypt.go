package kdfcrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// KDF should be implemented for different kdfs.
type KDF interface {
	SetDefaultParam()
	Generate(key, salt []byte, hashLength uint32) ([]byte, error)
}

// Option for generating hash from KDF.
type Option struct {
	Algorithm       string
	Param           string
	RandomSaltLenth uint32
	Salt            string
	HashLength      uint32
}

var mapKDF = make(map[string]reflect.Type)

func init() {
	RegisterKDF("argon2i", (*Argon2i)(nil))
	RegisterKDF("argon2id", (*Argon2id)(nil))
	RegisterKDF("pbkdf2", (*PBKDF2)(nil))
	RegisterKDF("scrypt", (*Scrypt)(nil))
	RegisterKDF("hkdf", (*HKDF)(nil))
}

func compareBytes(b1, b2 []byte) bool {
	if subtle.ConstantTimeEq(int32(len(b1)), int32(len(b2))) == 0 {
		return false
	}
	if subtle.ConstantTimeCompare(b1, b2) == 1 {
		return true
	}
	return false
}

func traverseStructParam(stValue reflect.Value, handler func(string, string, reflect.Value) error) error {
	if stValue.Kind() != reflect.Struct {
		return nil
	}

	stType := stValue.Type()

	numField := stType.NumField()

	for i := 0; i < numField; i++ {
		field := stType.Field(i)
		fieldValue := stValue.FieldByName(field.Name)
		if field.Anonymous {
			if field.Type.Kind() != reflect.Struct {
				continue
			}
			err := traverseStructParam(fieldValue, handler)
			if err != nil {
				return err
			}
			continue
		}

		paramName := field.Tag.Get("param")
		if paramName == "" {
			continue
		}

		err := handler(paramName, field.Name, fieldValue)
		if err != nil {
			return err
		}
	}

	return nil
}

func setParamValue(paramName, fieldName string, value reflect.Value, paramMap map[string]string) error {
	if !value.CanSet() {
		return fmt.Errorf("Can not set unexported struct field: %s", fieldName)
	}

	strValue, ok := paramMap[paramName]
	if !ok {
		return nil
	}

	var bitSize int
	switch value.Kind() {
	case reflect.Int8, reflect.Uint8:
		bitSize = 8
	case reflect.Int16, reflect.Uint16:
		bitSize = 16
	case reflect.Int32, reflect.Uint32:
		bitSize = 32
	case reflect.Int64, reflect.Uint64:
		bitSize = 64
	}

	switch value.Kind() {
	case reflect.String:
		value.SetString(strValue)
	case reflect.Bool:
		v, err := strconv.ParseBool(strValue)
		if err != nil {
			return err
		}
		value.SetBool(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(strValue, 10, bitSize)
		if err != nil {
			return err
		}
		value.SetInt(v)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(strValue, 10, bitSize)
		if err != nil {
			return err
		}
		value.SetUint(v)
	default:
		return fmt.Errorf(`Can not set param value for "%s", type: %v`, paramName, value.Kind())
	}

	return nil
}

func getParamValue(paramName string, value reflect.Value) (string, error) {
	var paramValue string

	switch value.Kind() {
	case reflect.String:
		paramValue = value.String()
	case reflect.Bool:
		paramValue = strconv.FormatBool(value.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		paramValue = strconv.FormatInt(value.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		paramValue = strconv.FormatUint(value.Uint(), 10)
	default:
		return "", fmt.Errorf(`Can not get param value for "%s", type: %v`, paramName, value.Kind())
	}

	return fmt.Sprintf("%s=%s", paramName, paramValue), nil
}

func parseParam(kdf KDF, param string) error {
	paramMap := make(map[string]string)

	chunks := strings.Split(param, ",")
	for _, chunk := range chunks {
		if len(chunk) == 0 {
			continue
		}
		eqIndex := strings.Index(chunk, "=")
		if eqIndex <= 0 {
			return fmt.Errorf(`Invalid param chunk: "%s"`, chunk)
		}
		key := chunk[:eqIndex]
		value := chunk[eqIndex+1:]
		paramMap[key] = value
	}

	kdfValue := reflect.ValueOf(kdf).Elem()
	err := traverseStructParam(kdfValue, func(paramName, fieldName string, value reflect.Value) error {
		return setParamValue(paramName, fieldName, value, paramMap)
	})
	if err != nil {
		return err
	}

	return nil
}

func generateParam(kdf KDF) (string, error) {
	paramSlice := make([]string, 0)

	kdfValue := reflect.ValueOf(kdf).Elem()
	err := traverseStructParam(kdfValue, func(paramName, fieldName string, value reflect.Value) error {
		chunk, err := getParamValue(paramName, value)
		if err != nil {
			return err
		}

		paramSlice = append(paramSlice, chunk)
		return nil
	})
	if err != nil {
		return "", err
	}

	return strings.Join(paramSlice, ","), nil
}

func parseEncodedString(encoded string) (string, string, string, string) {
	var algorithm, param, salt, value string

	encoded = strings.Trim(encoded, "$")

	frags := strings.Split(encoded, "$")
	if len(frags) == 0 {
		return algorithm, param, salt, value
	}
	value = frags[len(frags)-1]

	frags = frags[:len(frags)-1]
	if len(frags) == 0 {
		return algorithm, param, salt, value
	}
	algorithm = frags[0]

	frags = frags[1:]
	if len(frags) == 0 {
		return algorithm, param, salt, value
	}
	salt = frags[len(frags)-1]

	frags = frags[:len(frags)-1]
	if len(frags) == 0 {
		return algorithm, param, salt, value
	}
	param = frags[0]

	return algorithm, param, salt, value
}

func generateEncodedString(key []byte, kdf KDF, algorithm string, salt []byte, hashLength uint32) (string, error) {
	if hashLength == 0 {
		hashLength = 32
	}

	salt64 := base64.RawStdEncoding.EncodeToString(salt)

	hashed, err := kdf.Generate(key, salt, hashLength)
	if err != nil {
		return "", err
	}
	hashed64 := base64.RawStdEncoding.EncodeToString(hashed)

	param, err := generateParam(kdf)
	if err != nil {
		return "", err
	}

	encoded := fmt.Sprintf("$%s$%s$%s$%s", algorithm, param, salt64, hashed64)

	return encoded, nil
}

// RegisterKDF register a KDF with algorithm name.
func RegisterKDF(algorithm string, kdf KDF) {
	mapKDF[algorithm] = reflect.TypeOf(kdf)
}

// ListKDFAlgorithms list all the available kdf algorithms.
func ListKDFAlgorithms() []string {
	keys := make([]string, 0, len(mapKDF))
	for algorithm := range mapKDF {
		keys = append(keys, algorithm)
	}
	return keys
}

// KDFName returns the algorithm name of the KDF.
func KDFName(kdf KDF) (string, error) {
	for algorithm, typeKDF := range mapKDF {
		if typeKDF == reflect.TypeOf(kdf) {
			return algorithm, nil
		}
	}
	return "", fmt.Errorf("KDF not registered")
}

// GenerateRandomSalt generates random salt.
func GenerateRandomSalt(saltLength uint32) ([]byte, error) {
	b := make([]byte, saltLength)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// CreateKDF creates key derivation function.
func CreateKDF(algorithm, param string) (KDF, error) {
	typeKDF, ok := mapKDF[algorithm]
	if !ok {
		return nil, fmt.Errorf("Algorithm not available: '%s'", algorithm)
	}

	kdf, ok := reflect.New(typeKDF.Elem()).Interface().(KDF)
	if !ok {
		return nil, fmt.Errorf("Not a valid KDF: %s", algorithm)
	}

	kdf.SetDefaultParam()

	err := parseParam(kdf, param)
	if err != nil {
		return nil, err
	}

	return kdf, nil
}

// EncodeFromKDF encode the key with the given KDF.
func EncodeFromKDF(key string, kdf KDF, salt string, hashLength uint32) (string, error) {
	algorithm, err := KDFName(kdf)
	if err != nil {
		return "", err
	}

	encoded, err := generateEncodedString([]byte(key), kdf, algorithm, []byte(salt), hashLength)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// Encode generates encoded key.
func Encode(key string, opt *Option) (string, error) {
	kdf, err := CreateKDF(opt.Algorithm, opt.Param)
	if err != nil {
		return "", err
	}

	var salt []byte
	if opt.Salt == "" && opt.RandomSaltLenth != 0 {
		salt, err = GenerateRandomSalt(opt.RandomSaltLenth)
		if err != nil {
			return "", fmt.Errorf("Generate random salt error: %s", err)
		}
	} else {
		salt = []byte(opt.Salt)
	}

	encoded, err := generateEncodedString([]byte(key), kdf, opt.Algorithm, salt, opt.HashLength)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// Verify key and encoded key.
func Verify(key, encoded string) (bool, error) {
	algorithm, param, salt, hashed := parseEncodedString(encoded)

	kdf, err := CreateKDF(algorithm, param)
	if err != nil {
		return false, err
	}

	saltOrigin, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}

	hashedOrigin, err := base64.RawStdEncoding.DecodeString(hashed)
	if err != nil {
		return false, err
	}

	newHashed, err := kdf.Generate([]byte(key), saltOrigin, uint32(len(hashedOrigin)))
	if err != nil {
		return false, err
	}

	match := compareBytes(newHashed, hashedOrigin)

	return match, nil
}
