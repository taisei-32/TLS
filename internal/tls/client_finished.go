package tls

import (
	"hash"

	"github.com/taisei-32/TLS/internal/tls/common"
)

var data = []byte("GET / HTTP/1.1\r\nHost: www.itotai.com\r\nConnection: close\r\n\r\n")

func ClientFinishedFactory(transcriptHash []byte, secretKey SecretKey, applicationKey []byte, hashFunc func() hash.Hash) []byte {
	hmac := GenHmac(hashFunc, secretKey.ClientFinishedKey, transcriptHash)
	handshakeText := ToHandshakeByteArr(ClientFinishedHandshake(hmac))
	cipherText := GenEncrypted(handshakeText, secretKey.ClientFinishedKey, secretKey.Hash)
	record := ToRecordByteArr(ClientFinishedRecord(cipherText))

	cipherText1 := GenEncrypted(data, applicationKey, secretKey.Hash)
	record1 := ToRecordByteArr(ClientApplicationRecord(cipherText1))

	record = append(record, record1...)
	return record
}

func ClientFinishedRecord(cipherText []byte) Record {
	return Record{
		ContentType:   []byte{byte(common.Handshake)},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        Uint16ToBytes(uint16((len(cipherText)))),
		Payload:       cipherText,
	}
}

func ClientApplicationRecord(cipherText []byte) Record {
	return Record{
		ContentType:   []byte{byte(common.Application)},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        Uint16ToBytes(uint16((len(cipherText)))),
		Payload:       cipherText,
	}
}

func ClientFinishedHandshake(hmac []byte) Handshake {
	msg := hmac
	return Handshake{
		HandshakeType: []byte{byte(common.Finished)},
		Length:        Uint24ToBytes(uint32((len(msg)))),
		msg:           msg,
	}
}
