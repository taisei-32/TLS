package common

type RecordType uint16

const (
	Invalid          RecordType = 0x00
	ChangeCipherSpec RecordType = 0x14
	Alert            RecordType = 0x15
	Handshake        RecordType = 0x16
	Application      RecordType = 0x17
	// Heartbeat        RecordType = 0xff
)

type HandshakeType uint8

const (
	ClientHello         HandshakeType = 0x01
	ServerHello         HandshakeType = 0x02
	EndOfEarlyData      HandshakeType = 0x05
	EncryptedExtensions HandshakeType = 0x08
	CertificateRequest  HandshakeType = 0x0c
	Certificate         HandshakeType = 0x0b
	CertificateVerify   HandshakeType = 0x0f
	Finished            HandshakeType = 0x14
	KeyUpdate           HandshakeType = 0x19
)

type ExtensionType uint16

const (
	ServerName                          ExtensionType = 0x0000
	MaxFragmentLength                   ExtensionType = 0x0001
	StatusRequest                       ExtensionType = 0x0005
	SupportedGroups                     ExtensionType = 0x000a
	SignatureAlgorithms                 ExtensionType = 0x000d
	UseSrtp                             ExtensionType = 0x000e
	Heartbeat                           ExtensionType = 0x000f
	ApplicationLayerProtocolNegotiation ExtensionType = 0x0010
	SignedCertificateTimestamp          ExtensionType = 0x0012
	ClientCertificateType               ExtensionType = 0x0013
	ServerCertificateType               ExtensionType = 0x0014
	Padding                             ExtensionType = 0x0015
	PreSharedKey                        ExtensionType = 0x0029
	EarlyData                           ExtensionType = 0x002a
	SupportedVersions                   ExtensionType = 0x002b
	Cookie                              ExtensionType = 0x002c
	PskKeyExchangeModes                 ExtensionType = 0x002d
	CertificateAuthorities              ExtensionType = 0x002f
	OidFilters                          ExtensionType = 0x0030
	PostHandshakeAuth                   ExtensionType = 0x0031
	SignatureAlgorithmsCert             ExtensionType = 0x0032
	KeyShare                            ExtensionType = 0x0033
)

type SignatureAlgorithm uint16

const (
	rsa_pkcs1_sha256       SignatureAlgorithm = 0x0401
	rsa_pkcs1_sha384       SignatureAlgorithm = 0x0501
	rsa_pkcs1_sha512       SignatureAlgorithm = 0x0601
	ecdsa_secp256r1_sha256 SignatureAlgorithm = 0x0403
	ecdsa_secp384r1_sha384 SignatureAlgorithm = 0x0503
	ecdsa_secp521r1_sha512 SignatureAlgorithm = 0x0603
	rsa_pss_rsae_sha256    SignatureAlgorithm = 0x0804
	rsa_pss_rsae_sha384    SignatureAlgorithm = 0x0805
	rsa_pss_rsae_sha512    SignatureAlgorithm = 0x0806
	ed25519                SignatureAlgorithm = 0x0807
	ed448                  SignatureAlgorithm = 0x0808
	rsa_pss_pss_sha256     SignatureAlgorithm = 0x0809
	rsa_pss_pss_sha384     SignatureAlgorithm = 0x080a
	rsa_pss_pss_sha512     SignatureAlgorithm = 0x080b
)

type SupportedGroup uint16

const (
	secp256r1 SupportedGroup = 0x0017
	secp384r1 SupportedGroup = 0x0018
	secp521r1 SupportedGroup = 0x0019
	x25519    SupportedGroup = 0x001D
	x448      SupportedGroup = 0x001E

	ffdhe2048 SupportedGroup = 0x0100
	ffdhe3072 SupportedGroup = 0x0101
	ffdhe4096 SupportedGroup = 0x0102
	ffdhe6144 SupportedGroup = 0x0103
	ffdhe8192 SupportedGroup = 0x0104
)

type PskKeyExchangeMode uint8

const (
	PskKe    PskKeyExchangeMode = 0x00
	PskDheKe PskKeyExchangeMode = 0x01
)

var (
	TLS_VERSION_1_3        = []byte{0x03, 0x04}
	TLS_AES_256_GCM_SHA384 = []byte{0x13, 0x02}
)
