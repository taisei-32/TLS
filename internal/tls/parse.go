package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

func ParseHandshake(handshake []byte) Handshake {
	handshakeType := handshake[:3]
	handshakeLength := handshake[3:6]
	handshakeMsg := handshake[6 : 6+BytesToInt24([3]byte(handshakeLength))]
	return Handshake{
		HandshakeType: handshakeType,
		Length:        [3]byte(handshakeLength),
		msg:           handshakeMsg,
	}
}

func ParseServerHello(packet []byte) (ServerHello, []byte) {
	contentType := packet[0:1]
	length := packet[1:4]
	version := packet[4:6]
	random := packet[6:38]
	sessionIDLength := packet[38]
	sessionID := packet[39 : 39+BytesToint8(sessionIDLength)]
	cipherSuiteStart := 39 + BytesToint8(sessionIDLength)
	cipherSuite := packet[cipherSuiteStart : cipherSuiteStart+2]
	compressionMethodStart := cipherSuiteStart + 2
	compressionMethod := packet[compressionMethodStart]
	extensionLengthStart := compressionMethodStart + 1
	extensionLength := packet[extensionLengthStart : extensionLengthStart+2]
	extension := packet[extensionLengthStart+2:]

	return ServerHello{
		ContentType:       contentType,
		Length:            length,
		Version:           version,
		Random:            random,
		SessionIDLength:   sessionIDLength,
		SessionID:         sessionID,
		CipherSuite:       cipherSuite,
		CompressionMethod: compressionMethod,
		ExtensionLength:   extensionLength,
	}, extension
}

func ParseServerHelloExtension(extension []byte) []TLSExtensions {
	start := 0
	var tlsExtensions []TLSExtensions
	var keyshare []TLSExtensions
	var versions []TLSExtensions

	// fmt.Println("Extension:", extension)
	for start+4 <= len(extension) {
		extensionType := extension[start : start+2]
		extensionLength := BytesToUint16(extension[start+2 : start+4])
		// fmt.Println("keyshare:", uint16(common.KeyShare))
		// fmt.Println("bytesToUint16:", BytesToUint16(extensionType))
		if start+4+int(extensionLength) > len(extension) {
			break
		}
		extensionValue := extension[start+4 : start+4+int(extensionLength)]

		switch BytesToUint16(extensionType) {
		case uint16(common.KeyShare):
			if len(extensionValue) >= 36 {
				value := map[string]interface{}{
					"Group":             extensionValue[0:2],
					"KeyExchangeLength": extensionValue[2:4],
					"KeyExchange":       extensionValue[4:],
				}
				keyshare = append(keyshare, TLSExtensions{
					Type:   extensionType,
					Length: extension[start+2 : start+4],
					Value:  value,
				})
			}
		case uint16(common.SupportedVersions):
			if len(extensionValue) >= 2 {
				versions = append(versions, TLSExtensions{
					Type:   extensionType,
					Length: extension[start+2 : start+4],
					Value:  extensionValue[0:2],
				})
			}
		}
		start += 4 + int(extensionLength)
	}

	tlsExtensions = append(tlsExtensions, keyshare...)
	tlsExtensions = append(tlsExtensions, versions...)

	// fmt.Println(tlsExtensions)

	return tlsExtensions
}

func ParseCipherSuite(cipherSuite []byte) CipherSuite {
	switch BytesToUint16(cipherSuite) {
	case uint16(common.TLS_AES_128_GCM_SHA256):
		fmt.Println("cipherSuite", "TLS_AES_128_GCM_SHA256")
		return CipherSuite{
			Algorithm: "AES",
			KeyLength: "128",
			Mode:      "GCM",
			Hash:      "SHA256",
		}
	case uint16(common.TLS_AES_256_GCM_SHA384):
		fmt.Println("cipherSuite", "TLS_AES_256_GCM_SHA384")
		return CipherSuite{
			Algorithm: "AES",
			KeyLength: "256",
			Mode:      "GCM",
			Hash:      "SHA384",
		}
	case uint16(common.TLS_CHACHA20_POLY1305_SHA256):
		fmt.Println("cipherSuite", "TLS_AES_128_GCM_SHA256")
		return CipherSuite{
			Algorithm: "CHACHA20",
			Mode:      "POLY1305",
			Hash:      "SHA256",
		}
	default:
		return CipherSuite{
			Algorithm: "error",
		}
	}
}

func ParseRawData(rawData []byte) (Handshake, Handshake, Handshake, Handshake) {
	encryptedExtensionsType := rawData[0]
	encryptedExtensionsLength := rawData[1:4]
	// log.Println("encryptedExtensionsLength:", encryptedExtensionsLength)
	encryptedExtensionsEnd := 4 + BytesToInt24([3]byte(encryptedExtensionsLength))
	// log.Println("encryptedExtensionsEnd:", encryptedExtensionsEnd)
	encryptedExtensionsMsg := rawData[4:encryptedExtensionsEnd]
	// log.Println("encryptedExtensionsMsg:", encryptedExtensionsMsg)
	certificateStart := encryptedExtensionsEnd
	// log.Println("certificateStart:", certificateStart)
	certificateType := rawData[certificateStart]
	// log.Println("certificateType:", certificateType)
	certificateLength := rawData[certificateStart+1 : certificateStart+4]
	// log.Println("certificateLength:", certificateLength)
	certificateEnd := certificateStart + 4 + BytesToInt24([3]byte(certificateLength))
	// log.Println("certificateEnd:", certificateEnd)
	certificateMsg := rawData[certificateStart+4 : certificateEnd]
	// log.Println("certificateMsg:", certificateMsg)

	certificateVerifyStart := certificateEnd
	certificateVerifyType := rawData[certificateVerifyStart]
	certificateVerifyLength := rawData[certificateVerifyStart+1 : certificateVerifyStart+4]
	certificateVerifyEnd := certificateVerifyStart + 4 + BytesToInt24([3]byte(certificateVerifyLength))
	certificateVerifyMsg := rawData[certificateVerifyStart+4 : certificateVerifyEnd]
	finishedStart := certificateVerifyEnd
	finishedType := rawData[finishedStart]
	finishedLength := rawData[finishedStart+1 : finishedStart+4]
	finishedEnd := finishedStart + 4 + BytesToInt24([3]byte(finishedLength))
	finishedMsg := rawData[finishedStart+4 : finishedEnd]

	return Handshake{
			HandshakeType: []byte{encryptedExtensionsType},
			Length:        [3]byte(encryptedExtensionsLength),
			msg:           encryptedExtensionsMsg,
		}, Handshake{
			HandshakeType: []byte{certificateType},
			Length:        [3]byte(certificateLength),
			msg:           certificateMsg,
		}, Handshake{
			HandshakeType: []byte{certificateVerifyType},
			Length:        [3]byte(certificateVerifyLength),
			msg:           certificateVerifyMsg,
		}, Handshake{
			HandshakeType: []byte{finishedType},
			Length:        [3]byte(finishedLength),
			msg:           finishedMsg,
		}
}

func ParseCertificateVerify(certificateVerify []byte) CertificateVerify {
	signatureScheme := certificateVerify[:2]
	signatureLength := BytesToUint16(certificateVerify[2:4])
	signature := certificateVerify[4 : 4+signatureLength]
	return CertificateVerify{
		SignatureScheme: signatureScheme,
		SignatureLength: signatureLength,
		Signature:       signature,
	}
}

func ParseCertificate(certificateHandshake Handshake) Certificate {
	certificateRequestContextLength := BytesToint8(certificateHandshake.msg[0])
	var certificateRequestContext []byte
	if certificateRequestContextLength == 0 {
		certificateRequestContext = nil
	} else {
		certificateRequestContext = certificateHandshake.msg[1 : 1+certificateRequestContextLength]
	}
	certificateListLength := BytesToInt24([3]byte(certificateHandshake.msg[1+certificateRequestContextLength : 1+certificateRequestContextLength+3]))
	certificateEntry := certificateHandshake.msg[1+certificateRequestContextLength+3:]

	certificateEntryList := GenCertificateEntry(certificateEntry)

	return Certificate{
		CertificateRequestContextLength: uint8(certificateRequestContextLength),
		CertificateRequestContext:       certificateRequestContext,
		CertificateListLength:           uint(certificateListLength),
		CertificateList:                 certificateEntryList,
	}
}

func ParseCertificateEntry(certificateEntry []byte) (CertificateEntry, []byte) {
	certDataLength := BytesToInt24([3]byte(certificateEntry[:3]))
	certData := certificateEntry[3 : 3+certDataLength]
	other := certificateEntry[3+certDataLength+2:]

	return CertificateEntry{
		CertDataLength: uint(certDataLength),
		CertData:       certData,
	}, other
}
