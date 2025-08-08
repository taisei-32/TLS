package tls

import "hash"

func GenTransScriptHash(ClientHello []byte, ServerHello []byte, hashFunc func() hash.Hash) []byte {
	transcript := append(ClientHello, ServerHello...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}

func GenTransScriptHash1(ClientHello []byte, ServerHello []byte, EncryptedExtensions Handshake, Certificate Handshake, hashFunc func() hash.Hash) []byte {
	EncryptedExtensionsRaw := ToClientHandshakeByteArr(EncryptedExtensions)
	CertificateRaw := ToClientHandshakeByteArr(Certificate)
	transcript := append(ClientHello, ServerHello...)
	transcript = append(transcript, EncryptedExtensionsRaw...)
	transcript = append(transcript, CertificateRaw...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}
