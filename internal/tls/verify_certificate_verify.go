package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type CertificateVerify struct {
	SignatureScheme []byte
	SignatureLength uint16
	Signature       []byte
}

type Key struct {
	PrivateKey     *ecdh.PrivateKey
	PublicKey      *ecdh.PublicKey
	ServerHelloKey *ecdh.PublicKey
	SharedKey      []byte
	HashAlgorithm  string
}

type RawSignature struct {
	R, S *big.Int
}

func VerifyCertificateVerifyFactory(handshake Handshake, transcriptHash []byte, hashAlgorithm string, certData []byte) {
	certificateVerifyRaw := ParseCertificateVerify(handshake.msg)

	var textToVerify []byte
	textToVerify = append(textToVerify, bytes.Repeat([]byte{0x20}, 64)...)
	textToVerify = append(textToVerify, []byte("TLS 1.3, server CertificateVerify")...)
	textToVerify = append(textToVerify, 0x00)
	textToVerify = append(textToVerify, transcriptHash...)

	hashToVerify := GenHash(hashAlgorithm, textToVerify)

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
