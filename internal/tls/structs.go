package tls

import (
	"crypto/ecdh"
	"hash"
	"math/big"
)

type Key struct {
	PrivateKey     *ecdh.PrivateKey
	PublicKey      *ecdh.PublicKey
	ServerHelloKey *ecdh.PublicKey
	SharedKey      []byte
	HashAlgorithm  string
}

type Record struct {
	ContentType   byte
	LegacyVersion [2]byte
	Length        uint16
	Payload       []byte
}

type Handshake struct {
	HandshakeType byte
	Length        int
	Msg           []byte
}

// Extensionsを []Extensionsの型にして、Toで変換するときに修正
type ClientHello struct {
	LegacyVersion            [2]byte
	Random                   [32]byte //opaque
	LegacySessionID          [32]byte //opaque
	CipherSuites             []byte
	LegacyCompressionMethods []byte // opaque
	Extensions               []byte
}

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

type ServerNameList struct {
	NameType   []byte
	NameLength []byte
	Name       []byte
}

type KeyShareList struct {
	NamedGroup        []byte
	KeyExchangeLength []byte
	KeyExchange       []byte
}

type ServerHello struct {
	ContentType       []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionIDLength   byte
	SessionID         []byte
	CipherSuite       []byte
	CompressionMethod byte
	ExtensionLength   []byte
	TLSExtensions     []TLSExtensions
}

type TLSExtensions struct {
	Type   []byte
	Length []byte
	Value  interface{}
}

type CipherSuite struct {
	Algorithm string
	KeyLength string
	Mode      string
	Hash      string
}

type ApplicationData struct {
	ContentType      byte
	Version          []byte
	Length           []byte
	EncryptedContent []byte
}

type Certificate struct {
	CertificateRequestContextLength uint8
	CertificateRequestContext       []byte
	CertificateListLength           uint
	CertificateList                 []CertificateEntry
}

type CertificateEntry struct {
	CertDataLength  uint //uin24
	CertData        []byte
	ExtensionLength []byte
	Extensions      []Extension // uint16
}

type CertificateVerify struct {
	SignatureScheme []byte
	SignatureLength uint16
	Signature       []byte
}

type Finished struct {
	VerifyData []byte
}

type HkdfLabel struct {
	Length        []byte
	LabelLength   byte
	Label         []byte
	ContextLength byte
	Context       []byte
}

type SecretKey struct {
	EarlySecret          []byte
	HandshakeSecret      []byte
	EarySecretState      []byte
	HandshakeSecretState []byte
	Hash                 func() hash.Hash
	// BinderKey []byte
	// ClientEarlyTrafficSecret []byte
	// ClientEarlyTrafficSecret []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ServerFinishedKey            []byte
	ClientFinishedKey            []byte
	MasterSecret                 []byte
}

type RawSignature struct {
	R, S *big.Int
}
