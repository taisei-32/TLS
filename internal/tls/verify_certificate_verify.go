package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

func VerifyCertificateVerifyFactory(handshake Handshake, transcriptHash []byte, hashAlgorithm string, certData []byte) {
	certificateVerifyRaw := ParseCertificateVerify(handshake.msg)

	var text []byte
	text = append(text, bytes.Repeat([]byte{0x20}, 64)...)
	text = append(text, []byte("TLS 1.3, server CertificateVerify")...)
	text = append(text, 0x00)
	text = append(text, transcriptHash...)

	hashToVerify := GenHash(hashAlgorithm, text)

	cert, _ := x509.ParseCertificate(certData)
	publicKey := cert.PublicKey.(*ecdsa.PublicKey)

	var sig RawSignature
	asn1.Unmarshal(certificateVerifyRaw.Signature, &sig)

	isValid := ecdsa.Verify(publicKey, hashToVerify[:], sig.R, sig.S)
	if !isValid {
		panic("signature was not verified")
	} else {
		fmt.Println("signature was verified!!!")
	}
}
