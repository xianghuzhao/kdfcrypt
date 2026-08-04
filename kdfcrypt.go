package kdfcrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrInvalidEncoding indicates that an encoded password is malformed.
	ErrInvalidEncoding = errors.New("invalid password encoding")
	// ErrInvalidParameter indicates that an option or KDF parameter is invalid.
	ErrInvalidParameter = errors.New("invalid KDF parameter")
	// ErrUnsupportedAlgorithm indicates that a KDF algorithm is not registered.
	ErrUnsupportedAlgorithm = errors.New("unsupported KDF algorithm")
)

// KDF is implemented by key derivation functions registered with this package.
type KDF interface {
	SetDefaultParam()
	Derive(password, salt []byte, hashLength uint32) ([]byte, error)
}

// Option configures Encode.
type Option struct {
	Algorithm        string
	Param            string
	RandomSaltLength uint32
	Salt             string
	HashLength       uint32
}

var (
	mapKDF   = make(map[string]reflect.Type)
	mapKDFMu sync.RWMutex
)

func init() {
	RegisterKDF("argon2i", (*Argon2i)(nil))
	RegisterKDF("argon2id", (*Argon2id)(nil))
	RegisterKDF("scrypt", (*Scrypt)(nil))
	RegisterKDF("pbkdf2", (*PBKDF2)(nil))
	RegisterKDF("hkdf", (*HKDF)(nil))
}

func compareBytes(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	return subtle.ConstantTimeCompare(b1, b2) == 1
}

func kdfStructValue(kdf KDF) (reflect.Value, error) {
	if kdf == nil {
		return reflect.Value{}, fmt.Errorf("%w: KDF must not be nil", ErrInvalidParameter)
	}
	value := reflect.ValueOf(kdf)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("%w: KDF must be a non-nil pointer to a struct", ErrInvalidParameter)
	}
	return value.Elem(), nil
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
		return fmt.Errorf("%w: cannot set unexported struct field %s", ErrInvalidParameter, fieldName)
	}

	strValue, ok := paramMap[paramName]
	if !ok {
		return nil
	}

	var bitSize int
	switch value.Kind() {
	case reflect.Int, reflect.Uint:
		bitSize = strconv.IntSize
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
		if strings.ContainsAny(strValue, ",$") {
			return fmt.Errorf("%w: %s contains a reserved character", ErrInvalidParameter, paramName)
		}
		value.SetString(strValue)
	case reflect.Bool:
		v, err := strconv.ParseBool(strValue)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidParameter, paramName, err)
		}
		value.SetBool(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(strValue, 10, bitSize)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidParameter, paramName, err)
		}
		value.SetInt(v)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(strValue, 10, bitSize)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidParameter, paramName, err)
		}
		value.SetUint(v)
	default:
		return fmt.Errorf("%w: cannot set %q with type %v", ErrInvalidParameter, paramName, value.Kind())
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
		return "", fmt.Errorf("%w: cannot get %q with type %v", ErrInvalidParameter, paramName, value.Kind())
	}

	return fmt.Sprintf("%s=%s", paramName, paramValue), nil
}

func parseParam(kdf KDF, param string, requireAll bool) error {
	paramMap := make(map[string]string)
	knownParams := make(map[string]struct{})

	kdfValue, err := kdfStructValue(kdf)
	if err != nil {
		return err
	}
	if err := traverseStructParam(kdfValue, func(paramName, _ string, _ reflect.Value) error {
		if _, exists := knownParams[paramName]; exists {
			return fmt.Errorf("%w: duplicate param tag %q", ErrInvalidParameter, paramName)
		}
		knownParams[paramName] = struct{}{}
		return nil
	}); err != nil {
		return err
	}

	if param != "" {
		chunks := strings.Split(param, ",")
		for _, chunk := range chunks {
			if chunk == "" {
				return fmt.Errorf("%w: empty parameter", ErrInvalidParameter)
			}
			eqIndex := strings.Index(chunk, "=")
			if eqIndex <= 0 {
				return fmt.Errorf("%w: invalid parameter %q", ErrInvalidParameter, chunk)
			}
			key := chunk[:eqIndex]
			value := chunk[eqIndex+1:]
			if _, ok := knownParams[key]; !ok {
				return fmt.Errorf("%w: unknown parameter %q", ErrInvalidParameter, key)
			}
			if _, exists := paramMap[key]; exists {
				return fmt.Errorf("%w: duplicate parameter %q", ErrInvalidParameter, key)
			}
			paramMap[key] = value
		}
	}

	if requireAll {
		for paramName := range knownParams {
			if _, ok := paramMap[paramName]; !ok {
				return fmt.Errorf("%w: missing parameter %q", ErrInvalidParameter, paramName)
			}
		}
	}

	err = traverseStructParam(kdfValue, func(paramName, fieldName string, value reflect.Value) error {
		return setParamValue(paramName, fieldName, value, paramMap)
	})
	if err != nil {
		return err
	}

	return nil
}

func generateParam(kdf KDF) (string, error) {
	paramSlice := make([]string, 0)

	kdfValue, err := kdfStructValue(kdf)
	if err != nil {
		return "", err
	}
	err = traverseStructParam(kdfValue, func(paramName, fieldName string, value reflect.Value) error {
		if value.Kind() == reflect.String && strings.ContainsAny(value.String(), ",$") {
			return fmt.Errorf("%w: parameter %q contains a reserved character", ErrInvalidParameter, paramName)
		}
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

type encodedPassword struct {
	algorithm string
	param     string
	salt      string
	hash      string
}

func parseEncodedString(encoded string) (encodedPassword, error) {
	frags := strings.Split(encoded, "$")
	if len(frags) != 5 || frags[0] != "" || frags[1] == "" || frags[4] == "" {
		return encodedPassword{}, fmt.Errorf("%w: expected $algorithm$params$salt$hash", ErrInvalidEncoding)
	}
	return encodedPassword{
		algorithm: frags[1],
		param:     frags[2],
		salt:      frags[3],
		hash:      frags[4],
	}, nil
}

func generateEncodedString(password []byte, kdf KDF, algorithm string, salt []byte, hashLength uint32) (string, error) {
	if algorithm == "" || strings.Contains(algorithm, "$") {
		return "", fmt.Errorf("%w: invalid algorithm name %q", ErrInvalidParameter, algorithm)
	}
	if hashLength == 0 {
		hashLength = 32
	}

	salt64 := base64.RawStdEncoding.EncodeToString(salt)

	hashed, err := kdf.Derive(password, salt, hashLength)
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

// RegisterKDF registers a KDF type with an algorithm name.
func RegisterKDF(algorithm string, kdf KDF) {
	mapKDFMu.Lock()
	defer mapKDFMu.Unlock()
	mapKDF[algorithm] = reflect.TypeOf(kdf)
}

// ListKDFAlgorithms lists all registered KDF algorithms in sorted order.
func ListKDFAlgorithms() []string {
	mapKDFMu.RLock()
	defer mapKDFMu.RUnlock()
	keys := make([]string, 0, len(mapKDF))
	for algorithm := range mapKDF {
		keys = append(keys, algorithm)
	}
	sort.Strings(keys)
	return keys
}

// KDFName returns the algorithm name of the KDF.
func KDFName(kdf KDF) (string, error) {
	kdfType := reflect.TypeOf(kdf)
	if kdfType == nil || kdfType.Kind() != reflect.Pointer || kdfType.Elem().Kind() != reflect.Struct {
		return "", fmt.Errorf("%w: invalid KDF type %T", ErrInvalidParameter, kdf)
	}
	mapKDFMu.RLock()
	defer mapKDFMu.RUnlock()
	algorithms := make([]string, 0, len(mapKDF))
	for algorithm := range mapKDF {
		algorithms = append(algorithms, algorithm)
	}
	sort.Strings(algorithms)
	for _, algorithm := range algorithms {
		typeKDF := mapKDF[algorithm]
		if typeKDF == kdfType {
			return algorithm, nil
		}
	}
	return "", fmt.Errorf("%w: KDF type %T is not registered", ErrUnsupportedAlgorithm, kdf)
}

// GenerateRandomSalt generates random salt.
func GenerateRandomSalt(saltLength uint32) ([]byte, error) {
	if uint64(saltLength) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("%w: salt length is too large", ErrInvalidParameter)
	}
	b := make([]byte, saltLength)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type paramValidator interface {
	validate() error
}

func createKDF(algorithm, param string, requireAll bool) (KDF, error) {
	if algorithm == "" || strings.Contains(algorithm, "$") {
		return nil, fmt.Errorf("%w: invalid algorithm name %q", ErrInvalidParameter, algorithm)
	}
	mapKDFMu.RLock()
	typeKDF, ok := mapKDF[algorithm]
	mapKDFMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
	if typeKDF == nil || typeKDF.Kind() != reflect.Pointer || typeKDF.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: registered type for %q is invalid", ErrInvalidParameter, algorithm)
	}

	kdf, ok := reflect.New(typeKDF.Elem()).Interface().(KDF)
	if !ok {
		return nil, fmt.Errorf("%w: registered type for %q does not implement KDF", ErrInvalidParameter, algorithm)
	}

	kdf.SetDefaultParam()

	if err := parseParam(kdf, param, requireAll); err != nil {
		return nil, err
	}
	if validator, ok := kdf.(paramValidator); ok {
		if err := validator.validate(); err != nil {
			return nil, err
		}
	}

	return kdf, nil
}

// CreateKDF creates a key derivation function.
func CreateKDF(algorithm, param string) (KDF, error) {
	return createKDF(algorithm, param, false)
}

// EncodeFromKDF encodes a password with the given KDF and salt.
func EncodeFromKDF(password string, kdf KDF, salt string, hashLength uint32) (string, error) {
	if _, err := kdfStructValue(kdf); err != nil {
		return "", err
	}
	algorithm, err := KDFName(kdf)
	if err != nil {
		return "", err
	}

	encoded, err := generateEncodedString([]byte(password), kdf, algorithm, []byte(salt), hashLength)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// Encode generates an encoded password hash.
func Encode(password string, opt *Option) (string, error) {
	if opt == nil {
		return "", fmt.Errorf("%w: option must not be nil", ErrInvalidParameter)
	}
	kdf, err := CreateKDF(opt.Algorithm, opt.Param)
	if err != nil {
		return "", err
	}

	var salt []byte
	if opt.Salt == "" {
		saltLength := opt.RandomSaltLength
		if saltLength == 0 {
			saltLength = 16
		}
		salt, err = GenerateRandomSalt(saltLength)
		if err != nil {
			return "", fmt.Errorf("generate random salt: %w", err)
		}
	} else {
		salt = []byte(opt.Salt)
	}

	encoded, err := generateEncodedString([]byte(password), kdf, opt.Algorithm, salt, opt.HashLength)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// Verify reports whether password matches an encoded password hash.
func Verify(password, encoded string) (bool, error) {
	parsed, err := parseEncodedString(encoded)
	if err != nil {
		return false, err
	}

	kdf, err := createKDF(parsed.algorithm, parsed.param, true)
	if err != nil {
		return false, err
	}

	saltOrigin, err := base64.RawStdEncoding.DecodeString(parsed.salt)
	if err != nil {
		return false, fmt.Errorf("%w: invalid salt: %v", ErrInvalidEncoding, err)
	}

	hashedOrigin, err := base64.RawStdEncoding.DecodeString(parsed.hash)
	if err != nil {
		return false, fmt.Errorf("%w: invalid hash: %v", ErrInvalidEncoding, err)
	}
	if len(hashedOrigin) == 0 || uint64(len(hashedOrigin)) > uint64(^uint32(0)) {
		return false, fmt.Errorf("%w: invalid hash length", ErrInvalidEncoding)
	}

	newHashed, err := kdf.Derive([]byte(password), saltOrigin, uint32(len(hashedOrigin)))
	if err != nil {
		return false, err
	}

	match := compareBytes(newHashed, hashedOrigin)

	return match, nil
}
