package tls

type ClientHelloExtensionType struct {
	ServerName          []byte
	SupportedGroup      []byte
	SignatureAlgorithms []byte
	SupportedVersions   []byte
	PskKeyExchangeModes []byte
	KeyShare            []byte
}

type Extension struct {
	ExtensionType   []byte
	ExtensionLength []byte
	ExtensionData   []byte
}

type ExtensionData struct {
	ListLength []byte
	List       []byte
}

type ServerName struct {
	Extension
}

type ServerNameExtensionData struct {
	ExtensionData
}

type ServerNameList struct {
	NameType   []byte
	NameLength []byte
	Name       []byte
}

type SupportedGroup struct {
	Extension
}

type SupportedGroupExtensionData struct {
	ExtensionData
}

type SignatureAlgorithms struct {
	Extension
}

type SignatureAlgorithmsExtensionData struct {
	ExtensionData
}

type SupportedVersion struct {
	Extension
}

type SupportedVersionExtensionData struct {
	ExtensionData
}

type PskKeyExchangeModes struct {
	Extension
}

type KeyShare struct {
	Extension
}

type KeyShareExtensionData struct {
	ExtensionData
}

type KeyShareList struct {
	NamedGroup        []byte
	KeyExchangeLength []byte
	KeyExchange       []byte
}

func ClientHelloExtensionFactory(publickey []byte, servername string) ClientHelloExtensionType {
	ServerNameData := ToExtensionByteArr(ServerNameFactory(servername))
	SupportedGroupData := ToExtensionByteArr(SupportedGroupFactory())
	SignatureAlgorithmData := ToExtensionByteArr(SignatureAlgorithmsFactory())
	SupportedVersionsData := ToExtensionByteArr(SupportedVersionsFactory())
	PskKeyExchangeModesData := ToExtensionByteArr(PskKeyExchangeModesFactory())
	KeyShareData := ToExtensionByteArr(KeyShareFactory(publickey))

	return ClientHelloExtensionType{
		ServerName:          ServerNameData,
		SupportedGroup:      SupportedGroupData,
		SignatureAlgorithms: SignatureAlgorithmData,
		SupportedVersions:   SupportedVersionsData,
		PskKeyExchangeModes: PskKeyExchangeModesData,
		KeyShare:            KeyShareData,
	}
}

// func ExtensionFactory(Type string, servername ...string) Extension {
// 	var ExtensionType int16
// 	ExtensionData := ToExtensionByteArr(ExtensionDataFactory(Type, servername))

// 	switch Type {
// 	case ServerName:
// 		ExtensionType = common.ServerName
// 	case SupportedGroup:
// 		ExtensionType = common.SupportedGroup
// 	case SignatureAlgorithms:
// 		ExtensionType = common.SignatureAlgorithms
// 	case SupportedVersions:
// 		ExtensionType = common.SupportedVersions
// 	case PskKeyExchangeModes:
// 		ExtensionType = common.PskKeyExchangeModes
// 	case KeyShare:
// 		ExtensionType = common.KeyShare
// 	}

// 	return Extension{
// 		ExtensionType: Uint16ToBytes(uint16(ExtensionType)),
// 		ExtensionLength: Uint16ToBytes(uint16(len(ExtensionData))),
// 		ExtensionData: ExtensionData,
// 	}
// }

// func ExtensionDataFactory(Type string, servername ...string) ExtensionData {
// 	var ListData []byte

// 	switch Type {
// 	case ServerName:
// 		ListData = ToServerNameListByteArr(ServerNameListFactory(servername))
// 	case SupportedGroup:
// 		ListData = []byte{0x00, 0x1d}
// 	case SignatureAlgorithms:
// 		ListData = []byte{
// 		0x04, 0x01,
// 		0x04, 0x03,
// 		0x08, 0x04,
// 		0x08, 0x07,
// 	}
// 	case SupportedVersions:
// 		ListData = []byte{0x03, 0x04}
// 	case PskKeyExchangeModes:
// 		ListData = []byte{0x01, 0x01}
// 	case KeyShare:
// 		ListData = ToKeyShareListByteArr(KeyShareListFactory(publickey, 0x001D))
// 	}
// 	return ExtensionData{
// 		ListLength: Uint16ToBytes(uint16(len(ListData))),
// 		List: ListData,
// 	}
// }

func ServerNameFactory(servername string) Extension {
	ServerNameExtensionData := ToExtensionDataByteArr(ServerNameExtensionDataFactory(servername))
	return Extension{
		ExtensionType:   []byte{0x00, 0x00},
		ExtensionLength: Uint16ToBytes(uint16(len(ServerNameExtensionData))),
		ExtensionData:   ServerNameExtensionData,
	}
}

func ServerNameExtensionDataFactory(servername string) ExtensionData {
	ServerNameData := ToServerNameListByteArr(ServerNameListFactory(servername))
	return ExtensionData{
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

func SupportedGroupFactory() Extension {
	SupportedGroupExtensionData := ToExtensionDataByteArr(SupportedGroupExtensionDataFactory())
	return Extension{
		ExtensionType:   []byte{0x00, 0x0a},
		ExtensionLength: Uint16ToBytes(uint16(len(SupportedGroupExtensionData))),
		ExtensionData:   SupportedGroupExtensionData,
	}
}

func SupportedGroupExtensionDataFactory() ExtensionData {
	supportedGroupListData := []byte{0x00, 0x1d}
	return ExtensionData{
		ListLength: Uint16ToBytes(uint16(len(supportedGroupListData))),
		List:       supportedGroupListData,
	}
}

func SignatureAlgorithmsFactory() Extension {
	SignatureAlgorithmsExtensionData := ToExtensionDataByteArr(SignatureAlgorithmsExtensionDataFactory())
	return Extension{
		ExtensionType:   []byte{0x00, 0x0d},
		ExtensionLength: Uint16ToBytes(uint16(len(SignatureAlgorithmsExtensionData))),
		ExtensionData:   SignatureAlgorithmsExtensionData,
	}
}

func SignatureAlgorithmsExtensionDataFactory() ExtensionData {
	SignatureAlgorithmsList := []byte{
		0x04, 0x01,
		0x04, 0x03,
		0x08, 0x04,
		0x08, 0x07,
	}

	return ExtensionData{
		ListLength: Uint16ToBytes(uint16(len(SignatureAlgorithmsList))),
		List:       SignatureAlgorithmsList,
	}
}

func SupportedVersionsFactory() Extension {
	SupportedVersionsExtensionData := ToExtensionDataByteArr(SupportedVersionExtensionDataFactory())
	return Extension{
		ExtensionType:   []byte{0x00, 0x2b},
		ExtensionLength: Uint16ToBytes(uint16(len(SupportedVersionsExtensionData))),
		ExtensionData:   SupportedVersionsExtensionData,
	}
}

func SupportedVersionExtensionDataFactory() ExtensionData {
	supportedVersionsData := []byte{0x03, 0x04}
	return ExtensionData{
		ListLength: []byte{byte(len(supportedVersionsData))},
		List:       supportedVersionsData,
	}
}

func PskKeyExchangeModesFactory() Extension {
	ListData := []byte{0x01, 0x01}
	return Extension{
		ExtensionType:   []byte{0x00, 0x2d},
		ExtensionLength: Uint16ToBytes(uint16(len(ListData))),
		ExtensionData:   ListData,
	}
}

func KeyShareFactory(publickey []byte) Extension {
	KeyShareData := ToExtensionDataByteArr(KeyShareExtensionFactory(publickey))
	return Extension{
		ExtensionType:   []byte{0x00, 0x33},
		ExtensionLength: Uint16ToBytes(uint16(len(KeyShareData))),
		ExtensionData:   KeyShareData,
	}
}

func KeyShareExtensionFactory(publickey []byte) ExtensionData {
	KeyX25519 := ToKeyShareListByteArr(KeyShareListFactory(publickey, 0x001D))
	return ExtensionData{
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
