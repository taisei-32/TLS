package tls

import (
	"crypto/ecdh"
	"hash"
	"math/big"
)

type HandshakeMessage interface {
	HandshakeMsg()
}

type RecordMessage interface {
	RecordMsg()
}

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

type Application struct {
	ContentType      byte
	Version          []byte
	Length           []byte
	EncryptedContent []byte
}

type Handshake struct {
	HandshakeType byte
	Length        uint32
	Msg           HandshakeMessage
}

func (ch ClientHello) HandshakeMsg()          {}
func (sh ServerHello) HandshakeMsg()          {}
func (sh EncryptedExtensions) HandshakeMsg()  {}
func (sh CertificateMsg) HandshakeMsg()       {}
func (sh CertificateVerifyMsg) HandshakeMsg() {}
func (sh FinishedMsg) HandshakeMsg()          {}

// Extensionsを []Extensionsの型にして、Toで変換するときに修正
type ClientHello struct {
	LegacyVersion            [2]byte
	Random                   [32]byte
	LegacySessionID          [32]byte
	CipherSuites             []byte
	LegacyCompressionMethods []byte
	Extensions               ClientHelloExtensionType
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

type EncryptedExtensions struct {
	Msg []byte
}

type CertificateMsg struct {
	Msg []byte
}

type CertificateVerifyMsg struct {
	Msg []byte
}

type FinishedMsg struct {
	Msg []byte
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
