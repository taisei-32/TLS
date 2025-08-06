package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

type ApplicationData struct {
	ContentType      byte
	Version          []byte
	Length           []byte
	EncryptedContent []byte
}

func DecryptHandshakeFactory(packet []byte, clientsecretkey SecretKey) ([]byte, error) {
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

	key := HKDFExpandLabel(clientsecretkey.ServerHandshakeTrafficSecret, "key", nil, KeyLen, clientsecretkey.Hash)
	iv := HKDFExpandLabel(clientsecretkey.ServerHandshakeTrafficSecret, "iv", nil, IvLen, clientsecretkey.Hash)

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

// func DecryptApplicationFactory{

// }

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
