package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

var serverName = "www.itotai.com"

var data = []byte(fmt.Sprintf(
	"GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n",
	serverName,
))

func ApplicationFactory(secretKey SecretKey, clientApplicationKey []byte) []byte {
	return ToRecordByteArr(ApplicationRecordFactory(secretKey, clientApplicationKey))
}

func ApplicationRecordFactory(secretKey SecretKey, clientApplicationKey []byte) Record {
	data = append(data, []byte{byte(common.Application)}...)
	encryptedData := GenEncrypted(data, clientApplicationKey, secretKey.Hash)
	return Record{
		ContentType:   byte(common.Application),
		LegacyVersion: [2]byte{0x03, 0x03},
		Length:        uint16((len(encryptedData))),
		Payload:       encryptedData,
	}
}
