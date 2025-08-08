package tls

import "hash"

func GenTransScriptHash(ClientHello []byte, ServerHello []byte, hashFunc func() hash.Hash) []byte {
	transcript := append(ClientHello, ServerHello...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHashCertificate(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToClientHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToClientHandshakeByteArr(Certificate)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHashCertificateVerify(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, CertificateVerify Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToClientHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToClientHandshakeByteArr(Certificate)
	CertificateVerifyRaw := ToClientHandshakeByteArr(CertificateVerify)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	transcript = append(transcript, CertificateVerifyRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}
