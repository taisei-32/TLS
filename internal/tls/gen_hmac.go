package tls

import (
	"crypto/hmac"
	"hash"
)

func GenHmac(hashFunc func() hash.Hash, key []byte, data []byte) []byte {
	hmac := hmac.New(hashFunc, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}
