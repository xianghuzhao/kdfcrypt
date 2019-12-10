package kdfcrypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

var hashFuncMap = map[string]func() hash.Hash{
	"md5":        md5.New,
	"sha1":       sha1.New,
	"sha224":     sha256.New224,
	"sha256":     sha256.New,
	"sha512":     sha512.New,
	"sha384":     sha512.New384,
	"sha512/224": sha512.New512_224,
	"sha512/256": sha512.New512_256,
}
