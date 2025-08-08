package tls

import "crypto/ecdh"

func ClientHelloFactory(servername string, publickey *ecdh.PublicKey) ClientHello {
	ExtensionsData := ToClientHelloExtensionTypeByteArr(ClientHelloExtensionFactory(publickey.Bytes(), servername))

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
