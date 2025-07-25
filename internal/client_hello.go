package internal

import "github.com/taisei-32/TLS/internal/util"

type ClientHello struct {
	LegacyVersion            [2]byte
	Random                   [32]byte
	LegacySessionID          [32]byte
	CipherSuites             []byte
	LegacyCompressionMethods []byte
	Extensions               []byte
	// ExtensionType     []byte
	// ExtensionTypeData []byte
}

// type Extension struct {
// 	ExtensionType     []byte
// 	ExtensionTypeData []byte
// }

func ClientHelloFactory() ClientHello {
	_, public, err := util.GenEcdhX25519()
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}

	ExtensionsData := CmpExtension(public.Bytes())

	return ClientHello{
		LegacyVersion:            [2]byte{0x03, 0x04}, // TLS 1.3
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
	arr = append(arr, clienthello.LegacySessionID[:]...)

	// スライスはそのまま append
	arr = append(arr, clienthello.CipherSuites...)
	arr = append(arr, clienthello.LegacyCompressionMethods...)

	// Extensions も連結したい場合は以下を追加
	arr = append(arr, clienthello.Extensions...)
	return arr
}
