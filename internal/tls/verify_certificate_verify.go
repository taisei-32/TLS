package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

func VerifyCertificateVerifyFactory(handshake Handshake, transcriptHash []byte, certData []byte) {
	certificateVerifyRaw := ParseCertificateVerify(handshake.msg)

	var text []byte
	text = append(text, bytes.Repeat([]byte{0x20}, 64)...)
	text = append(text, []byte("TLS 1.3, server CertificateVerify")...)
	text = append(text, 0x00)
	text = append(text, transcriptHash...)

	cert, _ := x509.ParseCertificate(certData)
	fmt.Println("cert", cert)
	certAlgorithm := cert.SignatureAlgorithm.String()
	var hashAlgorithm string
	if strings.Split(certAlgorithm, "-")[0] == "SHA256" || strings.Split(certAlgorithm, "-")[0] == "SHA3384" {
		hashAlgorithm = strings.Split(certAlgorithm, "-")[0]
	} else {
		hashAlgorithm = strings.Split(certAlgorithm, "-")[1]
	}
	hashToVerify := GenHash(hashAlgorithm, text)

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		publicKey := cert.PublicKey.(*ecdsa.PublicKey)

		fmt.Printf("DEBUG: Public Key Curve: %s\n", publicKey.Curve.Params().Name)
		var sig RawSignature
		asn1.Unmarshal(certificateVerifyRaw.Signature, &sig)
		fmt.Printf("DEBUG: Raw Signature from Server: %x\n", certificateVerifyRaw.Signature)

		fmt.Printf("DEBUG: Parsed R: %x\n", sig.R.Bytes())
		fmt.Printf("DEBUG: Parsed S: %x\n", sig.S.Bytes())

		isValid := ecdsa.Verify(publicKey, hashToVerify[:], sig.R, sig.S)
		if !isValid {
			panic("signature was not verified")
		} else {
			fmt.Println("signature was verified!!!")
		}
	case *rsa.PublicKey:
		fmt.Println("RSA")
		var hash crypto.Hash
		switch hashAlgorithm {
		case "SHA256":
			hash = crypto.SHA256
		case "SHA384":
			hash = crypto.SHA384
		default:
			panic("unsupported hash algorithm RSA")
		}
		err := rsa.VerifyPSS(pub, hash, hashToVerify, certificateVerifyRaw.Signature, nil)
		if err != nil {
			panic("RSA signature was not verified")
		}
	}
}
