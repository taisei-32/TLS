package tls

import (
	"crypto/sha256"
	"crypto/sha512"
)

func GenHash(hashAlgorithm string, data []byte) []byte {
	switch hashAlgorithm {
	case "SHA256":
		sum := sha256.Sum256(data)
		return sum[:]
	case "SHA384":
		sum := sha512.Sum384(data)
		return sum[:]
	default:
		panic("unsupported hash algorithm: " + hashAlgorithm)
	}
}
