# kdfcrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/xianghuzhao/kdfcrypt.svg)](https://pkg.go.dev/github.com/xianghuzhao/kdfcrypt)
[![Test](https://github.com/xianghuzhao/kdfcrypt/actions/workflows/test.yml/badge.svg)](https://github.com/xianghuzhao/kdfcrypt/actions/workflows/test.yml)

`kdfcrypt` is a Go library for deriving keys and encoding password hashes. It
stores the algorithm, parameters, salt, and derived hash in one string, so
multiple KDFs and parameter generations can coexist in the same application.

Supported algorithms are Argon2i, Argon2id, scrypt, PBKDF2, and HKDF. Use
Argon2id for new password hashes. HKDF is intended for deriving keys from
high-entropy key material, not for password storage.

The module requires Go 1.25 or later.

## Password hashing

The algorithm must be selected explicitly. If neither `Salt` nor
`RandomSaltLength` is set, `Encode` generates a 16-byte random salt.

```go
package main

import (
	"fmt"
	"log"

	"github.com/xianghuzhao/kdfcrypt"
)

func main() {
	encoded, err := kdfcrypt.Encode("password", &kdfcrypt.Option{
		Algorithm: "argon2id",
	})
	if err != nil {
		log.Fatal(err)
	}

	match, err := kdfcrypt.Verify("password", encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(match) // true
}
```

`Verify` accepts hashes generated with older parameters because every encoded
string contains its own parameters. Changing defaults only affects new calls
that omit `Option.Param`; it does not strengthen existing stored hashes.

## Defaults

Defaults apply only to fields omitted by the caller.

| Algorithm | Default parameters |
| --- | --- |
| Argon2id | `v=19,m=19456,t=2,p=1` |
| Argon2i | `v=19,m=65536,t=1,p=1` |
| scrypt | `N=131072,r=8,p=1` |
| PBKDF2 | `iter=600000,hash=sha256` |
| HKDF | `hash=sha512`, empty `info` |

The default derived hash length is 32 bytes. Password-hashing costs should be
benchmarked on the deployment hardware and explicitly adjusted when needed.
The defaults follow the baseline recommendations in the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## Options

```go
type Option struct {
	Algorithm        string // Required.
	Param            string // Comma-separated algorithm parameters.
	RandomSaltLength uint32 // Used when Salt is empty; zero defaults to 16.
	Salt             string // Explicit fixed salt; avoid for password storage.
	HashLength       uint32 // Zero defaults to 32.
}
```

An explicit non-empty `Salt` takes precedence over `RandomSaltLength`. The
high-level `Encode` API never generates a new empty salt. Code that explicitly
needs an empty salt can use `EncodeFromKDF`:

```go
kdf, err := kdfcrypt.CreateKDF("pbkdf2", "iter=600000,hash=sha256")
if err != nil {
	return err
}
encoded, err := kdfcrypt.EncodeFromKDF("password", kdf, "", 32)
```

Fixed or empty salts should not be used for password storage.

## Encoded format

Encoded passwords use Raw standard Base64 and exactly four `$`-separated
fields:

```text
$argon2id$v=19,m=19456,t=2,p=1$c2FsdA$aGFzaA
$ algorithm $ parameters              $ salt $ hash
```

Parsing is strict. Duplicate, unknown, missing, overflowing, or malformed
parameters are rejected. `Verify` is designed for encoded values loaded from
trusted application storage. It does not impose resource limits on valid KDF
cost parameters, so applications must not let an attacker supply an arbitrary
encoded string directly.

Malformed encodings, invalid parameters, and unavailable algorithms can be
classified with `errors.Is` and `ErrInvalidEncoding`, `ErrInvalidParameter`, or
`ErrUnsupportedAlgorithm`. A valid encoding with the wrong password returns
`false, nil`.

## Deriving encryption keys

For a 32-byte AES-256 key, preserve the KDF algorithm, parameters, and salt so
the same key can be derived again:

```go
kdf, err := kdfcrypt.CreateKDF("argon2id", "m=19456,t=2,p=1")
if err != nil {
	return err
}
salt, err := kdfcrypt.GenerateRandomSalt(16)
if err != nil {
	return err
}
key, err := kdf.Derive([]byte("password"), salt, 32)
```

HKDF can be used when the input is already high-entropy key material:

```go
kdf, err := kdfcrypt.CreateKDF("hkdf", "hash=sha512,info=example-context")
if err != nil {
	return err
}
key, err := kdf.Derive(masterSecret, salt, 32)
```

## Algorithm parameters

- Argon2i and Argon2id: `m` is memory in KiB, `t` is the number of passes,
  `p` is parallelism, and `v` is the Argon2 version.
- scrypt: `N` is the CPU/memory cost and must be a power of two greater than
  one, `r` is the block size, and `p` is parallelism.
- PBKDF2: `iter` is the iteration count and `hash` is the HMAC hash function.
- HKDF: `hash` is the HMAC hash function and `info` is optional context.

Supported PBKDF2 and HKDF hash names are `md5`, `sha1`, `sha224`, `sha256`,
`sha384`, `sha512`, `sha512/224`, and `sha512/256`.
