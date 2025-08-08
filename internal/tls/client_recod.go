package tls

import "crypto/ecdh"

func ClientHandshakeFactory(servername string, publickey *ecdh.PublicKey) Handshake {
	clinetHello := ToClientByteArr(ClientHelloFactory(servername, publickey))

	return Handshake{
		HandshakeType: []byte{0x01},
		Length:        Uint24ToBytes(uint32((len(clinetHello)))),
		msg:           clinetHello,
	}
}

func ClientHelloRecordFactory(clientHelloStr []byte) Record {
	return Record{
		ContentType:   []byte{0x16},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        Uint16ToBytes(uint16((len(clientHelloStr)))),
		Payload:       clientHelloStr,
	}
}
