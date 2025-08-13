package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

// var data = []byte("GET / HTTP/1.1\r\n\r\n")

func ClientFinishedFactory(transcriptHash []byte, secretKey SecretKey) []byte {

	verify_data := GenHmac(secretKey.Hash, secretKey.ClientFinishedKey, transcriptHash)
	handshakeText := ToHandshakeByteArr(ClientFinishedHandshake(verify_data))
	encrypted_payload := append(handshakeText, []byte{byte(common.Handshake)}...)
	cipherText := GenEncrypted(encrypted_payload, secretKey.ClientHandshakeTrafficSecret, secretKey.Hash)
	record := ToRecordByteArr(ClientFinishedRecord(cipherText))
	fmt.Printf("client finished:%x\n", ToRecordByteArr(ClientFinishedRecord(handshakeText)))

	// cipherText1 := GenEncrypted(data, applicationKey, secretKey.Hash)
	// record1 := ToRecordByteArr(ClientApplicationRecord(cipherText1))

	// record = append(record, record1...)

	return record
}

func ClientFinishedRecord(cipherText []byte) Record {
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
