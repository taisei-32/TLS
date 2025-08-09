package tls

import "hash"

func GenTransScriptHash(ClientHello []byte, ServerHello []byte, hashFunc func() hash.Hash) []byte {
	transcript := append(ClientHello, ServerHello...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHashCertificate(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToHandshakeByteArr(Certificate)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHashCertificateVerify(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, CertificateVerify Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToHandshakeByteArr(Certificate)
	CertificateVerifyRaw := ToHandshakeByteArr(CertificateVerify)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	transcript = append(transcript, CertificateVerifyRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHashClientFinished(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, CertificateVerify Handshake, Finished Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToHandshakeByteArr(Certificate)
	CertificateVerifyRaw := ToHandshakeByteArr(CertificateVerify)
	FinishedRaw := ToHandshakeByteArr(Finished)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	transcript = append(transcript, CertificateVerifyRaw...)
	transcript = append(transcript, FinishedRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}
