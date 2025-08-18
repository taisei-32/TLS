// package tls

// import (
// 	"encoding/binary"

// 	"github.com/taisei-32/TLS/internal/tls/common"
// )

// func Uint16ToBytes(n uint16) []byte {
// 	b := make([]byte, 2)
// 	binary.BigEndian.PutUint16(b, n)
// 	return b
// }

// func Uint24ToBytes(n uint32) [3]byte {
// 	var buf [3]byte
// 	b := make([]byte, 4)
// 	binary.BigEndian.PutUint32(b, n)
// 	copy(buf[:], b[1:])
// 	return buf
// }

// func ToRecordByteArr(ext Record) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.ContentType)
// 	arr = append(arr, ext.LegacyVersion[:]...)
// 	arr = append(arr, Uint16ToBytes(ext.Length)...)
// 	arr = append(arr, ext.Payload...)

// 	return arr
// }

// func ToHandshakeByteArr(ext Handshake) []byte {
// 	var arr []byte

// 	length := Uint24ToBytes(ext.Length)

// 	arr = append(arr, ext.HandshakeType)
// 	arr = append(arr, length[:]...)

// 	var msg []byte
// 	switch ext.HandshakeType {
// 	case byte(common.ClientHello):
// 		msg := ToClientHelloByteArr(ext.Msg)
// 	case byte(common.ServerHello):
// 		ToSeverHelloByteArr()
// 	case byte(common.EncryptedExtensions):
// 	case byte(common.Certificate):
// 	case byte(common.CertificateVerify):
// 	case byte(common.Finished):
// 	}
// 	arr = append(arr, ext.Msg...)

// 	return arr
// }

// func (ch ClientHello) HandshakeMsg() {}

// func ToClientHelloByteArr(msg ClientHello) []byte {
// 	var arr []byte

// 	arr = append(arr, msg.LegacyVersion[:]...)
// 	arr = append(arr, msg.Random[:]...)
// 	arr = append(arr, byte(len(msg.LegacySessionID)))
// 	arr = append(arr, msg.LegacySessionID[:]...)
// 	arr = append(arr, Uint16ToBytes(uint16(len(msg.CipherSuites)))...)
// 	arr = append(arr, msg.CipherSuites...)
// 	arr = append(arr, byte(len(msg.LegacyCompressionMethods)))
// 	arr = append(arr, msg.LegacyCompressionMethods...)

// 	extensions := ToClientHelloExtensionTypeByteArr(msg.Extensions)
// 	arr = append(arr, Uint16ToBytes(uint16(len(extensions)))...)
// 	arr = append(arr, extensions...)

// 	return arr
// }

// func ToSeverHelloByteArr(ext ServerHello) []byte {
// 	var arr []byte
// 	keyshare := ext.TLSExtensions[0]
// 	keyshare_value := keyshare.Value.(map[string]interface{})
// 	version := ext.TLSExtensions[1]

// 	arr = append(arr, ext.ContentType...)
// 	arr = append(arr, ext.Length...)
// 	arr = append(arr, ext.Version...)
// 	arr = append(arr, ext.Random...)
// 	arr = append(arr, ext.SessionIDLength)
// 	arr = append(arr, ext.SessionID...)
// 	arr = append(arr, ext.CipherSuite...)
// 	arr = append(arr, ext.CompressionMethod)
// 	arr = append(arr, ext.ExtensionLength...)
// 	arr = append(arr, keyshare.Type...)
// 	arr = append(arr, keyshare.Length...)
// 	arr = append(arr, keyshare_value["Group"].([]byte)...)
// 	arr = append(arr, keyshare_value["KeyExchangeLength"].([]byte)...)
// 	arr = append(arr, keyshare_value["KeyExchange"].([]byte)...)
// 	arr = append(arr, version.Type...)
// 	arr = append(arr, version.Length...)
// 	arr = append(arr, version.Value.([]byte)...)

// 	return arr
// }

// func ToEncryptedExtensionsByteArr(ext EncryptedExtensions) {

// }

// func ToCertificateByteArr(ext Certificate) {

// }

// func ToCertificateVerifyByteArr(ext CertificateVerify) {

// }

// func ToFinished(ext Finished) {

// }

// func ToExtensionByteArr(ext Extension) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.ExtensionType...)
// 	arr = append(arr, ext.ExtensionLength...)
// 	arr = append(arr, ext.ExtensionData...)

// 	return arr
// }

// func ToExtensionDataByteArr(ext ExtensionData) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.ListLength...)
// 	arr = append(arr, ext.List...)

// 	return arr
// }

// func ToServerNameListByteArr(ext ServerNameList) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.NameType...)
// 	arr = append(arr, ext.NameLength...)
// 	arr = append(arr, ext.Name...)

// 	return arr
// }

// func ToKeyShareListByteArr(ext KeyShareList) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.NamedGroup...)
// 	arr = append(arr, ext.KeyExchangeLength...)
// 	arr = append(arr, ext.KeyExchange...)

// 	return arr
// }

// func ToClientHelloExtensionTypeByteArr(ext ClientHelloExtensionType) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.ServerName...)
// 	arr = append(arr, ext.SupportedGroup...)
// 	arr = append(arr, ext.SignatureAlgorithms...)
// 	arr = append(arr, ext.SupportedVersions...)
// 	arr = append(arr, ext.PskKeyExchangeModes...)
// 	arr = append(arr, ext.KeyShare...)

// 	return arr
// }

// func ToHkdfLabelByteArr(ext HkdfLabel) []byte {
// 	var arr []byte

// 	arr = append(arr, ext.Length...)
// 	arr = append(arr, ext.LabelLength)
// 	arr = append(arr, ext.Label...)
// 	arr = append(arr, ext.ContextLength)
// 	arr = append(arr, ext.Context...)

// 	return arr
// }
