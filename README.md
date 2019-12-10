# Key derivation function for password hashing

[![GoDoc](https://godoc.org/github.com/xianghuzhao/kdfcrypt?status.svg)](https://godoc.org/github.com/xianghuzhao/kdfcrypt)

`kdfcrypt` is a library for using KDF (key derivation function) to
generate password hashing.

The currently supported KDFs are
[argon2](https://en.wikipedia.org/wiki/Argon2),
[scrypt](https://en.bitcoinwiki.org/wiki/Scrypt),
[pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) and
[hkdf](https://en.wikipedia.org/wiki/HKDF).
`argon2id` is the recommended choice for password hashing.

These algorithms are implemented in
[`golang.org/x/crypto`](https://godoc.org/golang.org/x/crypto).


## Example

### Password verification

```go
package main

import (
	"fmt"

	"github.com/xianghuzhao/kdfcrypt"
)

func main() {
	encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
		Algorithm:        "argon2id",
		Param:            "m=4096,t=1,p=1",
		RandomSaltLength: 16,
		HashLength:       32,
	})

	// $argon2id$v=19,m=4096,t=1,p=1$mD+rvcR+6nuAV6MJFOmDjw$IqfwTPk9RMGeOv4pCE1QiURuSoi655GUVjcQAk81eXM
	fmt.Println(encoded)

	match, _ := kdfcrypt.Verify("password", encoded)
	fmt.Println(match) // true
}
```


### Generate key for AES-256

For the case of getting a derived key for AES-256 (which needs a 32-byte key):

```go
kdf, err := kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
salt, err := kdfcrypt.GenerateRandomSalt(16)
aes256Key, err := kdf.Derive("password", salt, 32)
```

The KDF algorithm, param and salt must be preserved in order to get
the same key again.


## Format of the encoded password

Password will be encoded into a single string which could be safely
saved.

There are four parts of the encoded string which are splitted by "`$`".

1. The name of KDF.
2. Param string of the KDF, which depends on KDF.
3. Salt encoded with base64.
4. Hash key encoded with base64.

```
$argon2id$v=19,m=4096,t=1,p=1$4ns1ibGJDR6IQufkbT8E/w$WQ2lAwbDhZmZQMCMg74L00OHUFzn/IvbwDaxU6bgIys
$ KDF    $ param             $ salt (base64)        $ hash (base64)
```


## Option

The `Option` struct is passed as argument for `Encode`.

1. Algorithm: Could be one of `argon2id`, `argon2i`, `scrypt`, `pbkdf`,
   `hkdf`.
2. Param: String for the KDF param. Different items are separated by
   comma "`,`". The detailed items vary among different KDFs.
3. RandomSaltLength: The length for the random salt in byte. If `Salt`
   is not empty, `RandomSaltLength` will be ignored.
4. Salt: Salt for the hash.
5. HashLength: The length of the hash result in byte.

You are able to set the salt explicitly:

```go
encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "argon2id",
	Param:            "m=4096,t=1,p=1",
	Salt:             "This_is_fixed_salt",
	HashLength:       32,
})
```

If you would like to use random salt, do not set the `Salt` and set the
`RandomSaltLength`:

```go
encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "argon2id",
	Param:            "m=4096,t=1,p=1",
	RandomSaltLength: 16,
	HashLength:       32,
})
```

## Supported KDF

### Argon2

Two variants `argon2i` and `argon2id` are provided.

```go
encodedArgon2i, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "argon2i",
	Param:            "m=4096,t=1,p=1",
})
// $argon2i$v=19,m=4096,t=1,p=1$HGi1YMTQxF+LYrcsnAz2YQ$vB3J0eDGCeq2l8Ky96OqB1P9rr8KPOQZzEScZnq1IUA

encodedArgon2id, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "argon2id",
	Param:            "m=4096,t=1,p=1",
})
// $argon2id$v=19,m=4096,t=1,p=1$23wOTcL162eix5YdOdOvqg$Il5kKW+CX+s6a8d6LtEnQ5k0bvBnfkuZXKkXq+Krx1I
```

The param consists of three parts:

1. m: memory, memory usage.
2. t: iterations, CPU cost.
3. p: parallelism, number of threads.


### Scrypt

```go
encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "scrypt",
	Param:            "N=32768,r=8,p=1",
})
// $scrypt$N=32768,r=8,p=1$v3T+aMCko9ZsovBnyWIdxQ$GTDo1AEPht8SL8Q+3y0FvWpPvzn5ZZNpwoqG+WOLsyI
```

1. N: CPU/memory cost parameter, which must be a power of two greater
   than 1.
2. r: The blocksize parameter, which fine-tunes sequential memory read
   size and performance. 8 is commonly used.
3. p: Parallelization parameter.


### PBKDF2

```go
encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:        "pbkdf2",
	Param:            "iter=1024,hash=sha512",
})
// $pbkdf2$iter=1024,hash=sha512$fvGxGq7tHzPgTJ3lGvl6XQ$O19iePvAQtlZ7nC5f5cS4C76bur9qMLp6dlPdXFiFTc
```

The `iter` is the iteration count for PBKDF.

The `hash` type could be one of the followings:

* md5
* sha1
* sha224
* sha256
* sha512
* sha384
* sha512/224
* sha512/256


### HKDF

HKDF should not be used for password storage.

```go
kdf, err := kdfcrypt.CreateKDF("hkdf", "hash=sha512,info=hkdf-test")
salt, err := kdfcrypt.GenerateRandomSalt(16)
key, err := kdf.Derive("password", salt, 32)
```

The `hash` type is the same as PBKDF.
The `info` is optional.
