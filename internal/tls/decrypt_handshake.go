package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
	"golang.org/x/crypto/chacha20poly1305"
)

func DecryptHandshakeFactory(packet []byte, secretkey SecretKey, cipherSuite []byte) ([]byte, error) {
	applicationData := ApplicationData{
		ContentType:      packet[0],
		Version:          packet[1:3],
		Length:           packet[3:5],
		EncryptedContent: packet[5:],
	}

	// const (
	// 	KeyLen = 16
	// 	IvLen  = 12
	// )

	// key := HKDFExpandLabel(secretkey.ServerHandshakeTrafficSecret, "key", nil, KeyLen, secretkey.Hash)
	// iv := HKDFExpandLabel(secretkey.ServerHandshakeTrafficSecret, "iv", nil, IvLen, secretkey.Hash)

	recordHeader := []byte{applicationData.ContentType}
	recordHeader = append(recordHeader, applicationData.Version...)
	recordHeader = append(recordHeader, applicationData.Length...)

	// block, err := aes.NewCipher(key)
	// if err != nil {
	// 	panic("generate error AES")
	// }
	// aesgcm, err := cipher.NewGCM(block)
	// if err != nil {
	// 	panic("Generate error GCM")
	// }
	// nonce := xorNonce(iv, 0)

	// plaintext, err := aesgcm.Open(nil, nonce, applicationData.EncryptedContent, recordHeader)
	// if err != nil {
	// 	panic("Decrypted error")
	// }
	var plaintext []byte
	switch BytesToUint16(cipherSuite) {
	case uint16(common.TLS_AES_128_GCM_SHA256):
		plaintext = DecryptAESGCM(secretkey.ServerHandshakeTrafficSecret, secretkey, recordHeader, applicationData)
	case uint16(common.TLS_CHACHA20_POLY1305_SHA256):
		plaintext = DecryptChaChaPoly(secretkey.ServerHandshakeTrafficSecret, secretkey, recordHeader, applicationData)
	}
	return plaintext, nil
}

func DecryptApplicationFactory(packet []byte, secretkey SecretKey, serverApplicationKey []byte, cipherSuite []byte) ([]byte, error) {
	lenPacket := len(packet)
	startPacket := 0
	var plaintext []byte
	// recordIndex := uint64(0)
	// i := 0

	for startPacket < lenPacket {
		applicationData := ApplicationData{
			ContentType: packet[startPacket],
			Version:     packet[startPacket+1 : startPacket+3],
			Length:      packet[startPacket+3 : startPacket+5],
		}

		contentLen := BytesToUint16(applicationData.Length)
		start := startPacket + 5
		end := start + int(contentLen)
		applicationData.EncryptedContent = packet[start:end]

		fmt.Println("ContentType:", applicationData.ContentType)
		fmt.Println("Version:", applicationData.Version)
		fmt.Println("Length:", applicationData.Length)
		fmt.Println("EnryptedContent:", applicationData.EncryptedContent)

		// const (
		// 	KeyLen = 16
		// 	IvLen  = 12
		// )
		// key := HKDFExpandLabel(serverApplicationKey, "key", nil, KeyLen, secretkey.Hash)
		// iv := HKDFExpandLabel(serverApplicationKey, "iv", nil, IvLen, secretkey.Hash)

		recordHeader := []byte{applicationData.ContentType}
		recordHeader = append(recordHeader, applicationData.Version...)
		recordHeader = append(recordHeader, applicationData.Length...)
		switch BytesToUint16(cipherSuite) {
		case uint16(common.TLS_AES_128_GCM_SHA256):
			plaintext = DecryptAESGCM(serverApplicationKey, secretkey, recordHeader, applicationData)
		case uint16(common.TLS_CHACHA20_POLY1305_SHA256):
			plaintext = DecryptChaChaPoly(serverApplicationKey, secretkey, recordHeader, applicationData)
		}

		// block, err := aes.NewCipher(key)
		// if err != nil {
		// 	panic("generate error AES")
		// }
		// aesgcm, err := cipher.NewGCM(block)
		// if err != nil {
		// 	panic("Generate error GCM")
		// }

		// nonce := xorNonce(iv, recordIndex)
		// recordIndex++

		// plaintexttmp, err := aesgcm.Open(nil, nonce, applicationData.EncryptedContent, recordHeader)
		// if err != nil {
		// 	panic("Decrypted error")
		// }
		// fmt.Println("plainteTmp:", plaintexttmp)
		// plaintext = append(plaintext, plaintexttmp...)
		startPacket = end
		// if i == 2 || i == 1 {
		// 	fmt.Println(string(plaintexttmp))
		// }
		// i++
	}
	return plaintext, nil
}

func DecryptAESGCM(decryptedkey []byte, secretkey SecretKey, recordHeader []byte, applicationData ApplicationData) []byte {
	const (
		KeyLen = 16
		IvLen  = 12
	)
	key := HKDFExpandLabel(decryptedkey, "key", nil, KeyLen, secretkey.Hash)
	iv := HKDFExpandLabel(decryptedkey, "iv", nil, IvLen, secretkey.Hash)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("generate error AES")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("Generate error GCM")
	}
	nonce := xorNonce(iv, 0)

	plaintext, err := aesgcm.Open(nil, nonce, applicationData.EncryptedContent, recordHeader)
	if err != nil {
		panic("Decrypted error")
	}
	return plaintext
}

func DecryptChaChaPoly(decryptedkey []byte, secretkey SecretKey, recordHeader []byte, applicationData ApplicationData) []byte {
	const (
		KeyLen = 32
		IvLen  = 12
	)
	key := HKDFExpandLabel(decryptedkey, "key", nil, KeyLen, secretkey.Hash)
	iv := HKDFExpandLabel(decryptedkey, "iv", nil, IvLen, secretkey.Hash)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic("generate error AES")
	}

	nonce := xorNonce(iv, 0)
	plaintext, err := aead.Open(nil, nonce, applicationData.EncryptedContent, recordHeader)
	if err != nil {
		panic("Decrypted error")
	}
	return plaintext
}

func xorNonce(iv []byte, seq uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)

	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= seqBytes[7-i]
	}
	return nonce
}
