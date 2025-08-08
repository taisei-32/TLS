package tls

import (
	"encoding/binary"
)

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

func ToSeverHelloByteArr(ext ServerHello) []byte {
	var arr []byte
	keyshare := ext.TLSExtensions[0]
	keyshare_value := keyshare.Value.(map[string]interface{})
	version := ext.TLSExtensions[1]

	arr = append(arr, ext.ContentType...)
	arr = append(arr, ext.Length...)
	arr = append(arr, ext.Version...)
	arr = append(arr, ext.Random...)
	arr = append(arr, ext.SessionIDLength)
	arr = append(arr, ext.SessionID...)
	arr = append(arr, ext.CipherSuite...)
	arr = append(arr, ext.CompressionMethod)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, keyshare.Type...)
	arr = append(arr, keyshare.Length...)
	arr = append(arr, keyshare_value["Group"].([]byte)...)
	arr = append(arr, keyshare_value["KeyExchangeLength"].([]byte)...)
	arr = append(arr, keyshare_value["KeyExchange"].([]byte)...)
	arr = append(arr, version.Type...)
	arr = append(arr, version.Length...)
	arr = append(arr, version.Value.([]byte)...)

	return arr
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

func ToHandshakeByteArr(ext Handshake) []byte {
	var arr []byte

	arr = append(arr, ext.HandshakeType...)
	arr = append(arr, ext.Length[:]...)
	arr = append(arr, ext.msg...)

	return arr
}

func ToRecordByteArr(ext Record) []byte {
	var arr []byte

	arr = append(arr, ext.ContentType...)
	arr = append(arr, ext.LegacyVersion...)
	arr = append(arr, ext.Length...)
	arr = append(arr, ext.Payload...)

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

	arr = append(arr, ext.Length...)
	arr = append(arr, ext.LabelLength)
	arr = append(arr, ext.Label...)
	arr = append(arr, ext.ContextLength)
	arr = append(arr, ext.Context...)

	return arr
}
