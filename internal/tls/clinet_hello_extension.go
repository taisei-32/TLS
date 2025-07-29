package tls

type ClientHelloExtensionType struct {
	ServerName          []byte
	SupportedGroup      []byte
	SignatureAlgorithms []byte
	SupportedVersions   []byte
	PskKeyExchangeModes []byte
	KeyShare            []byte
}

// ここはもっといいやり方があるはず
type Extension struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type ExtensionData struct {
	ListLength []byte
	List       []byte
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

func ClientHelloExtensionFactory1(publickey []byte, servername string) ClientHelloExtensionType {
	ServerNameData := ToServerNameByteArr(ServerNameFactory(servername))
	SupportedGroupData := ToSuportedGroupByteArr(SupportedGroupFactory())
	SignatureAlgorithmData := ToSingnatureAlgorithmsByteArr(SignatureAlgorithmsFactory())
	SupportedVersionsData := ToSupportedVersionsByteArr(SupportedVersionsFactory())
	PskKeyExchangeModesData := ToPskKeyExchangeModesByteArr(PskKeyExchangeModesFactory())
	KeyShareData := ToKeyShareByteArr(KeyShareFactory(publickey))

	return ClientHelloExtensionType{
		ServerName:          ServerNameData,
		SupportedGroup:      SupportedGroupData,
		SignatureAlgorithms: SignatureAlgorithmData,
		SupportedVersions:   SupportedVersionsData,
		PskKeyExchangeModes: PskKeyExchangeModesData,
		KeyShare:            KeyShareData,
	}
}

func ServerNameFactory(servername string) ServerName {
	ServerNameExtensionData := ToServerNameExtensionByteArr(ServerNameExtensionDataFactory(servername))
	return ServerName{
		ExtensionType:   []byte{0x00, 0x00},
		ExtensionLength: Uint16ToBytes(uint16(len(ServerNameExtensionData))),
		ExtensionData:   ServerNameExtensionData,
	}
}

func ServerNameExtensionDataFactory(servername string) ServerNameExtensionData {
	ServerNameData := ToServerNameListByteArr(ServerNameListFactory(servername))
	return ServerNameExtensionData{
		ListLength: Uint16ToBytes(uint16(len(ServerNameData))),
		List:       ServerNameData,
	}
}

func ServerNameListFactory(servername string) ServerNameList {
	return ServerNameList{
		NameType:   []byte{0x00},
		NameLength: Uint16ToBytes(uint16(len(servername))),
		Name:       []byte(servername),
	}
}

func SupportedGroupFactory() SupportedGroup {
	SupportedGroupExtensionData := ToSupportedGroupExtensionDataByteArr(SupportedGroupExtensionDataFactory())
	return SupportedGroup{
		ExtensionType:   []byte{0x00, 0x0a},
		ExtensionLength: Uint16ToBytes(uint16(len(SupportedGroupExtensionData))),
		ExtensionData:   SupportedGroupExtensionData,
	}
}

func SupportedGroupExtensionDataFactory() SupportedGroupExtensionData {
	supportedGroupListData := []byte{0x00, 0x1d}
	return SupportedGroupExtensionData{
		ListLength: Uint16ToBytes(uint16(len(supportedGroupListData))),
		List:       supportedGroupListData,
	}
}

func SignatureAlgorithmsFactory() SignatureAlgorithms {
	SignatureAlgorithmsExtensionData := ToSignatureAlgorithmsExtensionDataByteArr(SignatureAlgorithmsExtensionDataFactory())
	return SignatureAlgorithms{
		ExtensionType:   []byte{0x00, 0x0d},
		ExtensionLength: Uint16ToBytes(uint16(len(SignatureAlgorithmsExtensionData))),
		ExtensionData:   SignatureAlgorithmsExtensionData,
	}
}

func SignatureAlgorithmsExtensionDataFactory() SignatureAlgorithmsExtensionData {
	SignatureAlgorithmsList := []byte{
		0x04, 0x01,
		0x04, 0x03,
		0x08, 0x04,
		0x08, 0x07,
	}

	return SignatureAlgorithmsExtensionData{
		ListLength: Uint16ToBytes(uint16(len(SignatureAlgorithmsList))),
		List:       SignatureAlgorithmsList,
	}
}

func SupportedVersionsFactory() SupportedVersion {
	SupportedVersionsExtensionData := ToSupportedVersionExtensionDataByteArr(SupportedVersionExtensionDataFactory())
	return SupportedVersion{
		ExtensionType:   []byte{0x00, 0x2b},
		ExtensionLength: Uint16ToBytes(uint16(len(SupportedVersionsExtensionData))),
		ExtensionData:   SupportedVersionsExtensionData,
	}
}

func SupportedVersionExtensionDataFactory() SupportedVersionExtensionData {
	supportedVersionsData := []byte{0x03, 0x04}
	return SupportedVersionExtensionData{
		ListLength: []byte{byte(len(supportedVersionsData))},
		List:       supportedVersionsData,
	}
}

func PskKeyExchangeModesFactory() PskKeyExchangeModes {
	ListData := []byte{0x01, 0x01}
	return PskKeyExchangeModes{
		ExtensionType:   []byte{0x00, 0x2d},
		ExtensionLength: Uint16ToBytes(uint16(len(ListData))),
		ExtensionData:   ListData,
	}
}

func KeyShareFactory(publickey []byte) KeyShare {
	KeyShareData := ToKeyShareExtensionDataByteArr(KeyShareExtensionFactory(publickey))
	return KeyShare{
		ExtensionType:   []byte{0x00, 0x33},
		ExtensionLength: Uint16ToBytes(uint16(len(KeyShareData))),
		ExtensionData:   KeyShareData,
	}
}

func KeyShareExtensionFactory(publickey []byte) KeyShareExtensionData {
	KeyX25519 := ToKeyShareListByteArr(KeyShareListFactory(publickey, 0x001D))
	return KeyShareExtensionData{
		ListLength: Uint16ToBytes(uint16(len(KeyX25519))),
		List:       KeyX25519,
	}
}

func KeyShareListFactory(publickey []byte, number int16) KeyShareList {
	return KeyShareList{
		NamedGroup:        Uint16ToBytes(uint16(number)),
		KeyExchangeLength: Uint16ToBytes(uint16(len(publickey))),
		KeyExchange:       publickey,
	}
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

func ToServerNameByteArr(ext ServerName) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToServerNameExtensionByteArr(ext ServerNameExtensionData) []byte {
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

func ToSuportedGroupByteArr(ext SupportedGroup) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToSupportedGroupExtensionDataByteArr(ext SupportedGroupExtensionData) []byte {
	var arr []byte

	arr = append(arr, ext.ListLength...)
	arr = append(arr, ext.List...)

	return arr
}

func ToSingnatureAlgorithmsByteArr(ext SignatureAlgorithms) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToSignatureAlgorithmsExtensionDataByteArr(ext SignatureAlgorithmsExtensionData) []byte {
	var arr []byte

	arr = append(arr, ext.ListLength...)
	arr = append(arr, ext.List...)

	return arr
}

func ToSupportedVersionsByteArr(ext SupportedVersion) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToSupportedVersionExtensionDataByteArr(ext SupportedVersionExtensionData) []byte {
	var arr []byte

	arr = append(arr, ext.ListLength...)
	arr = append(arr, ext.List...)

	return arr
}

func ToPskKeyExchangeModesByteArr(ext PskKeyExchangeModes) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToKeyShareByteArr(ext KeyShare) []byte {
	var arr []byte

	arr = append(arr, ext.ExtensionType...)
	arr = append(arr, ext.ExtensionLength...)
	arr = append(arr, ext.ExtensionData...)

	return arr
}

func ToKeyShareExtensionDataByteArr(ext KeyShareExtensionData) []byte {
	var arr []byte

	arr = append(arr, ext.ListLength...)
	arr = append(arr, ext.List...)

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
