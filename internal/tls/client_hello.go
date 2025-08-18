package tls

import "crypto/ecdh"

func ClientHelloRecordFactory(clientHelloStr Handshake) Record {
	length := 
	return Record{
		ContentType:   byte(0x16),
		LegacyVersion: [2]byte{0x03, 0x03},
		Length:        uint16((len(clientHelloStr))),
		Payload:       clientHelloStr,
	}
}

func ClientHandshakeFactory(servername string, publickey *ecdh.PublicKey) Handshake {
	clientHello := ClientHelloFactory(servername, publickey)
	length := uint32(len(ToClientByteArr(clientHello)))

	return Handshake{
		HandshakeType: byte(0x01),
		Length:        length,
		Msg:           clientHello,
	}
}

func ClientHelloFactory(servername string, publickey *ecdh.PublicKey) ClientHello {
	ExtensionsData := ClientHelloExtensionFactory(publickey.Bytes(), servername)

	// 値を渡すときにconstから呼び出せたら
	return ClientHello{
		LegacyVersion:            [2]byte{0x03, 0x03}, // TLS 1.3
		Random:                   Random32Bytes(),
		LegacySessionID:          Random32Bytes(),
		CipherSuites:             []byte{0x13, 0x01},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               ExtensionsData,
	}
}
