package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"
)

func GenEncrypted(plainText []byte, secretKey []byte, hashFunc func() hash.Hash) []byte {
	const (
		KeyLen = 16
		IvLen  = 12
	)

	key := HKDFExpandLabel(secretKey, "key", nil, KeyLen, hashFunc)
	iv := HKDFExpandLabel(secretKey, "iv", nil, IvLen, hashFunc)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic("generate error AES")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("Generate error GCM")
	}
	nonce := xorNonce(iv, 0)
	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	return cipherText
}
