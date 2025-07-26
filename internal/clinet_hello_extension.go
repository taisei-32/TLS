package internal

import "github.com/taisei-32/TLS/internal/util"

// type ExtensionStrunct struct {
// 	ServerName          []byte
// 	SupportedGroups     []byte
// 	SignatureAlgorithms []byte
// 	SupportedVersions   []byte
// 	PskKeyExchangeModes []byte
// 	KeyShare            []byte
// }

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

func ClientHelloExtensionFactory(publickey []byte) ClinetHelloExtension {
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
	keyshareData := []byte{}
	keyshareData = append(keyshareData, keyshareListLen...)
	keyshareData = append(keyshareData, keyshareEntry...)

	keyshareType := []byte{0x00, 0x33}
	keyshareTypeLength := util.Uint16ToBytes(uint16(len(keyshareData)))

	supportedVersions := []byte{0x03, 0x04}
	supportedVersionsList := append([]byte{byte(len(supportedVersions))}, supportedVersions...)

	supportedVersionsType := []byte{0x00, 0x2b}
	supportedVersionsTypeLength := util.Uint16ToBytes(uint16(len(supportedVersionsList)))

	return ClinetHelloExtension{
		KeyshareType:                keyshareType,
		KeyshareTypeLength:          keyshareTypeLength,
		KeyshareTypeData:            keyshareData,
		SupportedVersionsType:       supportedVersionsType,
		SupportedVersionsTypeLenght: supportedVersionsTypeLength,
		SupportedVersionsTypeData:   supportedVersionsList,
	}
}

func ToClientExtensionByteArr(ext ClinetHelloExtension) []byte {
	var arr []byte

	arr = append(arr, ext.SupportedVersionsType...)
	arr = append(arr, ext.SupportedVersionsTypeLenght...)
	arr = append(arr, ext.SupportedVersionsTypeData...)
	arr = append(arr, ext.KeyshareType...)
	arr = append(arr, ext.KeyshareTypeLength...)
	arr = append(arr, ext.KeyshareTypeData...)

	// fmt.Println("ToClientExtension: ", arr)

	return arr
}
