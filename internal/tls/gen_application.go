package tls

import "github.com/taisei-32/TLS/internal/tls/common"

var data = []byte("GET / HTTP/1.1\r\n\r\n")

func ApplicationFactory(secretKey SecretKey, clientApplicationKey []byte) []byte {
	return ToRecordByteArr(ApplicationRecordFactory(secretKey, clientApplicationKey))
}

func ApplicationRecordFactory(secretKey SecretKey, clientApplicationKey []byte) Record {
	encryptedData := GenEncrypted(data, clientApplicationKey, secretKey.Hash)
	encryptedData = append(encryptedData, []byte{byte(common.Application)}...)
	return Record{
		ContentType:   []byte{byte(common.Application)},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        Uint16ToBytes(uint16((len(encryptedData)))),
		Payload:       encryptedData,
	}
}
