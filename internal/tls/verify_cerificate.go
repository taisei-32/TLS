package tls

import (
	"crypto/x509"
	"fmt"
)

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

// type CerExtensions

type CertificateVerify struct {
	SignatureScheme uint16
	SignatureLength uint16
	Signature       []byte
}

type Finished struct {
	VerifyData []byte
}

func CertificateFactory(certificateHandshake Handshake) {
	certificateEntry := ParseCertificate(certificateHandshake)
	for _, certData := range certificateEntry.CertificateList {
		sub, issuer, before, afteer, al, _ := CertDataFactory(certData.CertData)
		fmt.Println("sub:", sub)
		fmt.Println("issuer:", issuer)
		fmt.Println("before:", before)
		fmt.Println("afteer:", afteer)
		fmt.Println("al:", al)
	}
	// certData :=
	// fmt.Printf
}

func CertDataFactory(certData []byte) (string, string, string, string, string, error) {
	cert, err := x509.ParseCertificate(certData)
	return cert.Subject.String(),
		cert.Issuer.String(),
		cert.NotBefore.String(),
		cert.NotAfter.String(),
		cert.SignatureAlgorithm.String(),
		err
}
