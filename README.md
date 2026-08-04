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

## Encoded format

An encoded password contains the KDF, parameters, salt, and hash:

```text
$argon2id$v=19,m=19456,t=2,p=1$c2FsdA$aGFzaA
$ KDF    $ parameters         $ salt $ hash
```

The `$` characters separate four fields:

- **KDF** identifies the key derivation function, such as `argon2id`,
  `argon2i`, `scrypt`, `pbkdf2`, or `hkdf`.
- **parameters** records the settings used to derive the hash. These parameters
  are specific to the selected KDF, so their names and meanings differ between
  Argon2, scrypt, PBKDF2, and HKDF. For example, Argon2id uses `v` for the
  Argon2 version, `m` for memory in KiB, `t` for the number of passes, and `p`
  for parallelism. Keeping these values in the encoded string allows hashes
  created with older settings to remain verifiable. See
  [Algorithm parameters](#algorithm-parameters) for the settings supported by
  each KDF.
- **salt** is the randomly generated salt encoded with Raw standard Base64. It
  is not secret; its purpose is to ensure that equal passwords produce
  different hashes.
- **hash** is the derived result encoded with Raw standard Base64. It is the
  value compared when verifying a password and cannot be decrypted back into
  the original password.

Encoded values passed to `Verify` should come from trusted application
storage.

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
	fmt.Println(encoded)

	match, err := kdfcrypt.Verify("password", encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(match) // true
}
```

The encoded string changes on every call because `Encode` generates a random
salt by default.

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

- [Argon2i and Argon2id](https://en.wikipedia.org/wiki/Argon2)
  - `v`: Argon2 version.
  - `m`: Memory usage in KiB.
  - `t`: Number of passes.
  - `p`: Degree of parallelism.
- [scrypt](https://en.wikipedia.org/wiki/Scrypt)
  - `N`: CPU and memory cost; it must be a power of two greater than one.
  - `r`: Block size.
  - `p`: Degree of parallelism.
- [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
  - `iter`: Iteration count.
  - `hash`: HMAC hash function.
- [HKDF](https://en.wikipedia.org/wiki/HKDF)
  - `hash`: HMAC hash function.
  - `info`: Optional context information.

Supported PBKDF2 and HKDF hash names are `md5`, `sha1`, `sha224`, `sha256`,
`sha384`, `sha512`, `sha512/224`, and `sha512/256`.
