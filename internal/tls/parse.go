package tls

import (
	"github.com/taisei-32/TLS/internal/tls/common"
)

func ParseRecord(recordBytes []byte) Record {
	contentType := recordBytes[0]
	legacyVersion := recordBytes[1:3]
	lengthInt := BytesToUint16(recordBytes[3:5])
	payloadBytes := recordBytes[5:]
	var payload Handshake

	switch contentType {
	case byte(common.Handshake):
		payload = ParseHandshake(payloadBytes)
	default:
		panic("unsupported contentType")
	}

	return Record{
		ContentType:   contentType,
		LegacyVersion: [2]byte(legacyVersion),
		Length:        lengthInt,
		Payload:       payload,
	}
}

func ParseA(Bytes []byte) A {
	return A{
		Msg: Bytes,
	}
}

func ParseHandshake(handshakeBytes []byte) Handshake {
	handshakeType := handshakeBytes[0]
	length := BytesToInt24([3]byte(handshakeBytes[1:4]))
	msgBytes := handshakeBytes[4 : 4+length]

	var msg HandshakeMessage

	switch handshakeType {
	// case byte(common.ClientHello):
	//     body= ParseClientHello(msgBytes)
	case byte(common.ServerHello):
		msg = ParseServerHello(msgBytes)
	// case byte(common.Certificate):
	// 	msg = ParseCertificate(msgBytes)
	default:
		panic("unsupported HandshakeType")
	}

	return Handshake{
		HandshakeType: handshakeType,
		Length:        uint32(length),
		Msg:           msg,
	}
}

func ParseServerHello(packet []byte) ServerHello {
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
	tlsExtensions := ParseServerHelloExtension(extension)

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
		TLSExtensions:     tlsExtensions,
	}
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
	// if cipherSuite[1] == byte{1} {
	// 	return
	// }
	// parts := strings.Split(string(cipherSuite), "_")
	return CipherSuite{
		Algorithm: "AES",
		KeyLength: "128",
		Mode:      "GCM",
		Hash:      "SHA256",
	}
}

func ParseRawData(rawData []byte) (Handshake, Handshake, Handshake, Handshake) {
	encryptedExtensionsHandshakeType := rawData[0]
	encryptedExtensionsLength := BytesToInt24([3]byte(rawData[1:4]))
	encryptedExtensionsEnd := 4 + encryptedExtensionsLength
	encryptedExtensionsMsg := ParseEncryptedExtensions(rawData[4:encryptedExtensionsEnd])

	certificateStart := encryptedExtensionsEnd
	certificateHandshakeType := rawData[certificateStart]
	certificateLength := BytesToInt24([3]byte(rawData[certificateStart+1 : certificateStart+4]))
	certificateEnd := certificateStart + 4 + certificateLength
	certificateMsg := Parsecertificate(rawData[certificateStart+4 : certificateEnd])

	certificateVerifyStart := certificateEnd
	certificateVerifyHandshakeType := rawData[certificateVerifyStart]
	certificateVerifyLength := BytesToInt24([3]byte(rawData[certificateVerifyStart+1 : certificateVerifyStart+4]))
	certificateVerifyEnd := certificateVerifyStart + 4 + certificateVerifyLength
	certificateVerifyMsg := ParsecertificateVerify(rawData[certificateVerifyStart+4 : certificateVerifyEnd])

	finishedStart := certificateVerifyEnd
	finishedHandshakeType := rawData[finishedStart]
	finishedLength := BytesToInt24([3]byte(rawData[finishedStart+1 : finishedStart+4]))
	finishedEnd := finishedStart + 4 + finishedLength
	finishedMsg := ParseFinished(rawData[finishedStart+4 : finishedEnd])

	return Handshake{
			HandshakeType: byte(encryptedExtensionsHandshakeType),
			Length:        uint32(encryptedExtensionsLength),
			Msg:           encryptedExtensionsMsg,
		}, Handshake{
			HandshakeType: byte(certificateHandshakeType),
			Length:        uint32(certificateLength),
			Msg:           certificateMsg,
		}, Handshake{
			HandshakeType: byte(certificateVerifyHandshakeType),
			Length:        uint32(certificateVerifyLength),
			Msg:           certificateVerifyMsg,
		}, Handshake{
			HandshakeType: byte(finishedHandshakeType),
			Length:        uint32(finishedLength),
			Msg:           finishedMsg,
		}
}

func ParseEncryptedExtensions(encryptedExtensions []byte) EncryptedExtensions {
	return EncryptedExtensions{
		Msg: encryptedExtensions,
	}
}

func Parsecertificate(certificateMsg []byte) CertificateMsg {
	return CertificateMsg{
		Msg: certificateMsg,
	}
}

func ParsecertificateVerify(certificateVerifyMsg []byte) CertificateVerifyMsg {
	return CertificateVerifyMsg{
		Msg: certificateVerifyMsg,
	}
}

func ParseFinished(finished []byte) FinishedMsg {
	return FinishedMsg{
		Msg: finished,
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
	certificateRequestContextLength := BytesToint8(certificateHandshake.Msg[0])
	var certificateRequestContext []byte
	if certificateRequestContextLength == 0 {
		certificateRequestContext = nil
	} else {
		certificateRequestContext = certificateHandshake.Msg[1 : 1+certificateRequestContextLength]
	}
	certificateListLength := BytesToInt24([3]byte(certificateHandshake.Msg[1+certificateRequestContextLength : 1+certificateRequestContextLength+3]))
	certificateEntry := certificateHandshake.Msg[1+certificateRequestContextLength+3:]

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
