package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/taisei-32/TLS/internal/tls/common"
	"golang.org/x/crypto/chacha20poly1305"
)

func GenEncrypted(plainText []byte, secretKey []byte, hashFunc func() hash.Hash, cipherSuite []byte) []byte {
	var cipherText []byte
	switch BytesToUint16(cipherSuite) {
	case uint16(common.TLS_AES_128_GCM_SHA256):
		cipherText = EncryptAESGCM(plainText, secretKey, hashFunc)
	case uint16(common.TLS_CHACHA20_POLY1305_SHA256):
		cipherText = EncryptChaChaPoly(plainText, secretKey, hashFunc)
	}

	return cipherText
}

func EncryptAESGCM(plainText []byte, secretKey []byte, hashFunc func() hash.Hash) []byte {
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
	aad := []byte{byte(common.Application), 0x03, 0x03}
	aad = append(aad, Uint16ToBytes(uint16(len(plainText)+aesgcm.Overhead()))...)
	cipherText := aesgcm.Seal(nil, nonce, plainText, aad)
	return cipherText
}

func EncryptChaChaPoly(plainText []byte, secretKey []byte, hashFunc func() hash.Hash) []byte {
	const (
		KeyLen = 32
		IvLen  = 12
	)
	key := HKDFExpandLabel(secretKey, "key", nil, KeyLen, hashFunc)
	iv := HKDFExpandLabel(secretKey, "iv", nil, IvLen, hashFunc)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	nonce := xorNonce(iv, 0)
	aad := []byte{byte(common.Application), 0x03, 0x03}
	aad = append(aad, Uint16ToBytes(uint16(len(plainText)+aead.Overhead()))...)
	cipherText := aead.Seal(nil, nonce, plainText, aad)
	return cipherText
}
