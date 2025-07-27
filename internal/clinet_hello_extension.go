package internal

import (
	"github.com/taisei-32/TLS/internal/util"
)

// 修正
type ClientHelloExtensionType struct {
	ServerName          []byte
	SupportedGroup      []byte
	SignatureAlgorithms []byte
	SupportedVersions   []byte
	PskKeyExchangeModes []byte
	KeyShare            []byte
}

// server_name
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//
//	├─ Server Name List Length
//	└─ Server Name List
//	   └─ [エントリ1]
//	      ├─ Name Type
//	      ├─ Name Length
//	      └─ Server Name
type ServerName struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type ServerNameExtensionData struct {
	ListLength []byte
	List       []byte
}

type ServerNameList struct {
	NameType   []byte
	NameLength []byte
	Name       []byte
}

// supported_group
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//    ├─ Supported Versions List Length
//    └─ Supported Versions List
//       ├─ Version 1
//       └─ Version 2

type SupportedGroup struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type SupportedGroupExtensionData struct {
	ListLength []byte
	List       []byte
}

// signature_algorithms
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//    ├─ Signature Algorithms List Length
//    └─ Signature Algorithms List
//       ├─ Signature Scheme 1
//       ├─ Signature Scheme 2

type SignatureAlgorithms struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type SignatureAlgorithmsExtensionData struct {
	ListLength []byte
	List       []byte
}

// supported_version
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//    ├─ Supported Versions List Length
//    └─ Supported Versions List
//       ├─ Version 1
//       ├─ Version 2

type SupportedVersion struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type SupportedVersionExtensionData struct {
	ListLength []byte
	List       []byte
}

// psk_key_exchange_moded
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//    ├─ KE Modes List Length
//    └─ KE Modes List
//       └─ KE Mode

type PskKeyExchangeModes struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type PskKeyExchangeModesExtensionData struct {
	ListLength []byte
	List       []byte
}

// key_share
// ├─ 拡張タイプ
// ├─ 拡張全体の長さ
// └─ 拡張データ
//    ├─ Client Key Share List Length
//    └─ Client Key Share List
//       └─ [Key Share Entry 1]
//          ├─ Named Group
//          ├─ Key Exchange Length
//          └─ Key Exchange

type KeyShare struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type KeyShareExtensionData struct {
	ListLength []byte
	List       []byte
}

type KeyShareList struct {
	NamedGroup        []byte
	KeyExchangeLength []byte
	KeyExchange       []byte
}

type ClinetHelloExtension struct {
	ServerNameType              []byte
	ServerNameLength            []byte
	ServerNameData              []byte
	SupportedGroupsType         []byte
	SupportedGroupsLength       []byte
	SupportedGroupsData         []byte
	SignatureAlgorithmsType     []byte
	SignatureAlgorithmsLength   []byte
	SignatureAlgorithmsData     []byte
	SupportedVersionsType       []byte
	SupportedVersionsTypeLenght []byte
	SupportedVersionsTypeData   []byte
	PskKeyExchangeModesType     []byte
	PskKeyExchangeModesLength   []byte
	PskKeyExchangeModesData     []byte
	KeyshareType                []byte
	KeyshareTypeLength          []byte
	KeyshareTypeData            []byte
}

type Keyshare struct {
	KeyXGroup       []byte
	KeyXGroupLength []byte
	KeyXGroupData   []byte
}

func ClientHelloExtensionFactory(publickey []byte, servername string) ClinetHelloExtension {
	servernameData := []byte(servername)
	servernameLength := util.Uint16ToBytes(uint16(len(servernameData)))

	serverNameEntry := []byte{0x00}
	serverNameEntry = append(serverNameEntry, servernameLength...)
	serverNameEntry = append(serverNameEntry, servernameData...)

	serverNameListLength := util.Uint16ToBytes(uint16(len(serverNameEntry)))
	serverNameData := append(serverNameListLength, serverNameEntry...)

	serverNameType := []byte{0x00, 0x00}
	serverNameLength := util.Uint16ToBytes(uint16(len(serverNameData)))

	supportedGroupsList := []byte{
		0x00, 0x1d,
	}
	supportedGroupsListLength := util.Uint16ToBytes(uint16(len(supportedGroupsList)))
	supportedGroupsData := append(supportedGroupsListLength, supportedGroupsList...)

	supportedGroupsType := []byte{0x00, 0x0a}
	supportedGroupsLength := util.Uint16ToBytes(uint16(len(supportedGroupsData)))

	signatureSchemes := []byte{
		0x04, 0x01,
		0x04, 0x03,
		0x08, 0x04,
		0x08, 0x07,
	}
	signatureSchemesLength := util.Uint16ToBytes(uint16(len(signatureSchemes)))
	signatureAlgorithmsData := append(signatureSchemesLength, signatureSchemes...)

	signatureAlgorithmType := []byte{0x00, 0x0d}
	signatureAlgorithmsLength := util.Uint16ToBytes(uint16(len(signatureAlgorithmsData)))

	supportedVersions := []byte{0x03, 0x04}
	supportedVersionsList := append([]byte{byte(len(supportedVersions))}, supportedVersions...)
	supportedVersionsType := []byte{0x00, 0x2b}
	supportedVersionsTypeLength := util.Uint16ToBytes(uint16(len(supportedVersionsList)))

	pskKeyExchangeModesData := []byte{0x01, 0x01}
	pskKeyExchangeModesType := []byte{0x00, 0x2d}
	pskKeyExchangeModesLength := util.Uint16ToBytes(uint16(len(pskKeyExchangeModesData)))

	keyshare := Keyshare{
		KeyXGroup:     []byte{0x00, 0x1d},
		KeyXGroupData: publickey,
	}
	keyshare.KeyXGroupLength = util.Uint16ToBytes(uint16(len(keyshare.KeyXGroupData)))

	keyshareEntry := []byte{}
	keyshareEntry = append(keyshareEntry, keyshare.KeyXGroup...)
	keyshareEntry = append(keyshareEntry, keyshare.KeyXGroupLength...)
	keyshareEntry = append(keyshareEntry, keyshare.KeyXGroupData...)

	keyshareListLen := util.Uint16ToBytes(uint16(len(keyshareEntry)))
	keyshareData := append(keyshareListLen, keyshareEntry...)

	keyshareType := []byte{0x00, 0x33}
	keyshareTypeLength := util.Uint16ToBytes(uint16(len(keyshareData)))

	return ClinetHelloExtension{
		ServerNameType:              serverNameType,
		ServerNameLength:            serverNameLength,
		ServerNameData:              serverNameData,
		SupportedGroupsType:         supportedGroupsType,
		SupportedGroupsLength:       supportedGroupsLength,
		SupportedGroupsData:         supportedGroupsData,
		SignatureAlgorithmsType:     signatureAlgorithmType,
		SignatureAlgorithmsLength:   signatureAlgorithmsLength,
		SignatureAlgorithmsData:     signatureAlgorithmsData,
		SupportedVersionsType:       supportedVersionsType,
		SupportedVersionsTypeLenght: supportedVersionsTypeLength,
		SupportedVersionsTypeData:   supportedVersionsList,
		PskKeyExchangeModesType:     pskKeyExchangeModesType,
		PskKeyExchangeModesLength:   pskKeyExchangeModesLength,
		PskKeyExchangeModesData:     pskKeyExchangeModesData,
		KeyshareType:                keyshareType,
		KeyshareTypeLength:          keyshareTypeLength,
		KeyshareTypeData:            keyshareData,
	}
}

func ToClientExtensionByteArr(ext ClinetHelloExtension) []byte {
	var arr []byte

	arr = append(arr, ext.ServerNameType...)
	arr = append(arr, ext.ServerNameLength...)
	arr = append(arr, ext.ServerNameData...)

	arr = append(arr, ext.SupportedGroupsType...)
	arr = append(arr, ext.SupportedGroupsLength...)
	arr = append(arr, ext.SupportedGroupsData...)

	arr = append(arr, ext.SignatureAlgorithmsType...)
	arr = append(arr, ext.SignatureAlgorithmsLength...)
	arr = append(arr, ext.SignatureAlgorithmsData...)

	arr = append(arr, ext.SupportedVersionsType...)
	arr = append(arr, ext.SupportedVersionsTypeLenght...)
	arr = append(arr, ext.SupportedVersionsTypeData...)

	arr = append(arr, ext.PskKeyExchangeModesType...)
	arr = append(arr, ext.PskKeyExchangeModesLength...)
	arr = append(arr, ext.PskKeyExchangeModesData...)

	arr = append(arr, ext.KeyshareType...)
	arr = append(arr, ext.KeyshareTypeLength...)
	arr = append(arr, ext.KeyshareTypeData...)

	return arr
}
