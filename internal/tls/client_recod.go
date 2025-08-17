package tls

import "crypto/ecdh"

func ClientHandshakeFactory(servername string, publickey *ecdh.PublicKey) Handshake {
	clinetHello := ToClientByteArr(ClientHelloFactory(servername, publickey))

	return Handshake{
		HandshakeType: byte(0x01),
		Length:        uint32((len(clinetHello))),
		Msg:           clinetHello,
	}
}

func ClientHelloRecordFactory(clientHelloStr []byte) Record {
	return Record{
		ContentType:   byte(0x16),
		LegacyVersion: [2]byte{0x03, 0x03},
		Length:        uint16((len(clientHelloStr))),
		Payload:       clientHelloStr,
	}
}
