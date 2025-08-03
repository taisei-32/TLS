package tls

import "encoding/binary"

func Uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

func Uint24ToBytes(n uint32) [3]byte {
	var buf [3]byte
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	copy(buf[:], b[1:])
	return buf
}

func ToClientByteArr(clienthello ClientHello) []byte {
	var arr []byte

	arr = append(arr, clienthello.LegacyVersion[:]...)
	arr = append(arr, clienthello.Random[:]...)
	arr = append(arr, byte(len(clienthello.LegacySessionID)))
	arr = append(arr, clienthello.LegacySessionID[:]...)
	arr = append(arr, Uint16ToBytes(uint16(len(clienthello.CipherSuites)))...)
	arr = append(arr, clienthello.CipherSuites...)
	arr = append(arr, byte(len(clienthello.LegacyCompressionMethods)))
	arr = append(arr, clienthello.LegacyCompressionMethods...)
	arr = append(arr, Uint16ToBytes(uint16(len(clienthello.Extensions)))...)
	arr = append(arr, clienthello.Extensions...)

	return arr
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

func ToExtensionByteArr(ext Extension) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToExtensionDataByteArr(ext ExtensionData) []byte {
	var arr []byte

	arr = append(arr, ext.ListLength...)
	arr = append(arr, ext.List...)

	return arr
}

func ToServerNameListByteArr(ext ServerNameList) []byte {
	var arr []byte

	arr = append(arr, ext.NameType...)
	arr = append(arr, ext.NameLength...)
	arr = append(arr, ext.Name...)

	return arr
}

func ToKeyShareListByteArr(ext KeyShareList) []byte {
	var arr []byte

	arr = append(arr, ext.NamedGroup...)
	arr = append(arr, ext.KeyExchangeLength...)
	arr = append(arr, ext.KeyExchange...)

	return arr
}

func ToClientHelloExtensionTypeByteArr(ext ClientHelloExtensionType) []byte {
	var arr []byte

	arr = append(arr, ext.ServerName...)
	arr = append(arr, ext.SupportedGroup...)
	arr = append(arr, ext.SignatureAlgorithms...)
	arr = append(arr, ext.SupportedVersions...)
	arr = append(arr, ext.PskKeyExchangeModes...)
	arr = append(arr, ext.KeyShare...)

	return arr
}

func ToHkdfLabelByteArr(ext HkdfLabel) []byte {
	var arr []byte

	arr = append(arr, Uint16ToBytes(uint16(ext.length))...)
	arr = append(arr, []byte(ext.label)...)
	arr = append(arr, ext.context...)

	return arr
}
