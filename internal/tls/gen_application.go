package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

func ApplicationFactory(secretKey SecretKey, clientApplicationKey []byte, cipherSuite []byte, hostname string) []byte {
	return ToRecordByteArr(ApplicationRecordFactory(secretKey, clientApplicationKey, cipherSuite, hostname))
}

func ApplicationRecordFactory(secretKey SecretKey, clientApplicationKey []byte, cipherSuite []byte, hostname string) Record {
	var serverName = hostname

	var data = []byte(fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n",
		serverName,
	))
	data = append(data, []byte{byte(common.Application)}...)
	encryptedData := GenEncrypted(data, clientApplicationKey, secretKey.Hash, cipherSuite)
	return Record{
		ContentType:   []byte{byte(common.Application)},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        Uint16ToBytes(uint16((len(encryptedData)))),
		Payload:       encryptedData,
	}
}
