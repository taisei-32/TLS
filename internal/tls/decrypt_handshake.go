package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func DecryptHandshakeFactory(packet []byte, secretkey SecretKey) ([]byte, error) {
	applicationData := ApplicationData{
		ContentType:      packet[0],
		Version:          packet[1:3],
		Length:           packet[3:5],
		EncryptedContent: packet[5:],
	}

	const (
		KeyLen = 16
		IvLen  = 12
	)

	key := HKDFExpandLabel(secretkey.ServerHandshakeTrafficSecret, "key", nil, KeyLen, secretkey.Hash)
	iv := HKDFExpandLabel(secretkey.ServerHandshakeTrafficSecret, "iv", nil, IvLen, secretkey.Hash)

	recordHeader := []byte{applicationData.ContentType}
	recordHeader = append(recordHeader, applicationData.Version...)
	recordHeader = append(recordHeader, applicationData.Length...)

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
	return plaintext, nil
}

func DecryptApplicationFactory(packet []byte, secretkey SecretKey, serverApplicationKey []byte) ([]byte, error) {
	applicationData := ApplicationData{
		ContentType:      packet[0],
		Version:          packet[1:3],
		Length:           packet[3:5],
		EncryptedContent: packet[5:],
	}

	const (
		KeyLen = 16
		IvLen  = 12
	)

	key := HKDFExpandLabel(serverApplicationKey, "key", nil, KeyLen, secretkey.Hash)
	iv := HKDFExpandLabel(serverApplicationKey, "iv", nil, IvLen, secretkey.Hash)

	recordHeader := []byte{applicationData.ContentType}
	recordHeader = append(recordHeader, applicationData.Version...)
	recordHeader = append(recordHeader, applicationData.Length...)

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
	return plaintext, nil
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
