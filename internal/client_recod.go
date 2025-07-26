package internal

import (
	"github.com/taisei-32/TLS/internal/util"
)

type RecordClientHello struct {
	ContentType   []byte
	LegacyVersion []byte
	Length        []byte
	Payload       []byte
}

type HandshakeClientHello struct {
	HandshakeType []byte
	Length        [3]byte
	clientHello   []byte
}

func ClientHandshakeFactory() HandshakeClientHello {
	clinetHello := ToClientByteArr(ClientHelloFactory())

	return HandshakeClientHello{
		HandshakeType: []byte{0x01},
		Length:        util.Uint24ToBytes(uint32((len(clinetHello)))),
		clientHello:   clinetHello,
	}
}

func ClientHelloRecordFactory() RecordClientHello {
	handshakeclient := ToClientHandshakeByteArr(ClientHandshakeFactory())

	return RecordClientHello{
		ContentType:   []byte{0x16},
		LegacyVersion: []byte{0x03, 0x03},
		Length:        util.Uint16ToBytes(uint16((len(handshakeclient)))),
		Payload:       handshakeclient,
	}
}

func ToClientHandshakeByteArr(ext HandshakeClientHello) []byte {
	var arr []byte

	arr = append(arr, ext.HandshakeType...)
	arr = append(arr, ext.Length[:]...)
	arr = append(arr, ext.clientHello...)

	// fmt.Println("ToClientHandshake: ", arr)

	return arr
}

func ToClientRecordByteArr(ext RecordClientHello) []byte {
	var arr []byte

	arr = append(arr, ext.ContentType...)
	arr = append(arr, ext.LegacyVersion...)
	arr = append(arr, ext.Length...)
	arr = append(arr, ext.Payload...)

	// fmt.Println("ToClientRecord: ", arr)

	return arr
}
