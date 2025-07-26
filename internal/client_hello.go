package internal

import (
	"github.com/taisei-32/TLS/internal/util"
)

type ClientHello struct {
	LegacyVersion            [2]byte
	Random                   [32]byte //opaque
	LegacySessionID          [32]byte //opaque
	CipherSuites             []byte
	LegacyCompressionMethods []byte // opaque
	Extensions               []byte
}

// type Extension struct {
// 	ExtensionType     []byte
// 	ExtensionLength   []byte
// 	ExtensionTypeData []byte
// }

func ClientHelloFactory(servername string) ClientHello {
	_, public, err := util.GenEcdhX25519()
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}

	ExtensionsData := ToClientExtensionByteArr(ClientHelloExtensionFactory(public.Bytes(), servername))

	return ClientHello{
		LegacyVersion:            [2]byte{0x03, 0x03}, // TLS 1.3
		Random:                   util.Random32Bytes(),
		LegacySessionID:          util.Random32Bytes(),
		CipherSuites:             []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               ExtensionsData,
		// Extensions: []Extension{
		// 	{
		// 		ExtensionType:     []byte{0x01, 0x09},
		// 		ExtensionTypeData: public.Bytes(),
		// 	},
		// },
	}
}

func ToClientByteArr(clienthello ClientHello) []byte {
	var arr []byte

	arr = append(arr, clienthello.LegacyVersion[:]...)
	arr = append(arr, clienthello.Random[:]...)
	arr = append(arr, byte(len(clienthello.LegacySessionID)))
	arr = append(arr, clienthello.LegacySessionID[:]...)
	arr = append(arr, util.Uint16ToBytes(uint16(len(clienthello.CipherSuites)))...)
	arr = append(arr, clienthello.CipherSuites...)
	arr = append(arr, byte(len(clienthello.LegacyCompressionMethods)))
	arr = append(arr, clienthello.LegacyCompressionMethods...)
	arr = append(arr, util.Uint16ToBytes(uint16(len(clienthello.Extensions)))...)
	arr = append(arr, clienthello.Extensions...)

	return arr
}
