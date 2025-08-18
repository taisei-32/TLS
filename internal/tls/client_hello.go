package tls

import (
	"crypto/ecdh"

	"github.com/taisei-32/TLS/internal/tls/common"
)

func ClientHelloFactory(servername string, publickey *ecdh.PublicKey) ClientHello {
	ExtensionsData := ToClientHelloExtensionTypeByteArr(ClientHelloExtensionFactory(publickey.Bytes(), servername))
	var ciphereSuite []byte
	ciphereSuite = append(ciphereSuite, Uint16ToBytes(uint16(common.TLS_AES_128_GCM_SHA256))...)
	ciphereSuite = append(ciphereSuite, Uint16ToBytes(uint16(common.TLS_AES_256_GCM_SHA384))...)
	ciphereSuite = append(ciphereSuite, Uint16ToBytes(uint16(common.TLS_CHACHA20_POLY1305_SHA256))...)

	// 値を渡すときにconstから呼び出せたら
	return ClientHello{
		LegacyVersion:            [2]byte{0x03, 0x03}, // TLS 1.3
		Random:                   Random32Bytes(),
		LegacySessionID:          Random32Bytes(),
		CipherSuites:             ciphereSuite,
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               ExtensionsData,
	}
}
