package tls

type CipherSuite struct {
	Algorithm string
	KeyLength string
	Mode      string
	Hash      string
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

func ParseRawData(rawData []byte) Handshake {
	// encryptedExtensionsType := rawData[0]
	encryptedExtensionsLength := rawData[1:4]
	// log.Println("encryptedExtensionsLength:", encryptedExtensionsLength)
	encryptedExtensionsEnd := 4 + BytesToInt24([3]byte(encryptedExtensionsLength))
	// log.Println("encryptedExtensionsEnd:", encryptedExtensionsEnd)
	// encryptedExtensionsMsg := rawData[4:encryptedExtensionsEnd]
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

	// certificateVerifyStart := certificateEnd
	// certificateVerifyType := rawData[certificateVerifyStart]
	// certificateVerifyLength := rawData[certificateVerifyStart+1 : certificateVerifyStart+4]
	// certificateVerifyEnd := certificateVerifyStart + 4 + BytesToInt24([3]byte(certificateVerifyLength))
	// certificateVerifyMsg := rawData[certificateVerifyStart+4 : certificateVerifyEnd]
	// finishedStart := certificateVerifyEnd
	// finishedType := rawData[finishedStart]
	// finishedLength := rawData[finishedStart+1 : finishedStart+4]
	// finishedEnd := finishedStart + 4 + BytesToInt24([3]byte(finishedLength))
	// finishedMsg := rawData[finishedStart+4 : finishedEnd]

	return Handshake{
		HandshakeType: []byte{certificateType},
		Length:        [3]byte(certificateLength),
		msg:           certificateMsg,
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
