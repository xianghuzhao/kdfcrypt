# Key derivation function for password hashing

[![GoDoc](https://godoc.org/github.com/xianghuzhao/kdfcrypt?status.svg)](https://godoc.org/github.com/xianghuzhao/kdfcrypt)

`kdfcrypt` is a library for using KDF (key derivation function) to
generate password hashing.

The currently supported algorithms are
[argon2](https://en.wikipedia.org/wiki/Argon2),
[pbkdf2](https://en.wikipedia.org/wiki/PBKDF2),
[scrypt](https://en.bitcoinwiki.org/wiki/Scrypt) and
[hkdf](https://en.wikipedia.org/wiki/HKDF).
The algorithms are implemented by
[`golang.org/x/crypto`](https://godoc.org/golang.org/x/crypto).


## Example

```go
encoded, _ := kdfcrypt.Encode("password", &kdfcrypt.Option{
	Algorithm:       "argon2id",
	RandomSaltLenth: 16,
	Param:           "m=4096,t=1,p=1",
})

fmt.Println(encoded)  // $argon2id$v=19,m=4096,t=1,p=1$4ns1ibGJDR6IQufkbT8E/w$WQ2lAwbDhZmZQMCMg74L00OHUFzn/IvbwDaxU6bgIys

match, _ := kdfcrypt.Verify("password", encoded)
fmt.Println(match) // true
```
