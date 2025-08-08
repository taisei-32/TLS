package tls

import (
	"crypto/x509"
	"fmt"
)

func CertificateFactory(certificateHandshake Handshake) []byte {
	certificateEntry := ParseCertificate(certificateHandshake)
	certs := VerifyCertificataionX509(certificateEntry.CertificateList)
	fmt.Println("証明書有効!!!")
	VerifyCertificataionOCSP(certs)
	return certificateEntry.CertificateList[0].CertData
}

// func CertDataFactory(certData []byte) (string, string, string, string, string, error) {
// 	cert, err := x509.ParseCertificate(certData)
// 	return cert.Subject.String(),
// 		cert.Issuer.String(),
// 		cert.NotBefore.String(),
// 		cert.NotAfter.String(),
// 		cert.SignatureAlgorithm.String(),
// 		err
// }

func VerifyCertificataionX509(certificateList []CertificateEntry) []*x509.Certificate {
	certsEntry := make([]*x509.Certificate, len(certificateList))
	for i, entry := range certificateList {
		cert, err := x509.ParseCertificate(entry.CertData)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		certsEntry[i] = cert
	}
	intermediatePool := x509.NewCertPool()
	for _, cert := range certsEntry[1:] {
		intermediatePool.AddCert(cert)
	}
	rootPool, _ := x509.SystemCertPool()
	opts := x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootPool,
	}
	_, err := certsEntry[0].Verify(opts)
	if err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	//todo 証明書の失効確認
	return certsEntry
}

func VerifyCertificataionOCSP(certs []*x509.Certificate) error {

}
