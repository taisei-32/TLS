package tls

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

func GetHash(hashAlgorithm string) func() hash.Hash {
	switch hashAlgorithm {
	case "SHA256":
		return sha256.New
	case "SHA384":
		return sha512.New384
	}
	panic("unsupported hash algorithm: " + hashAlgorithm)
}
