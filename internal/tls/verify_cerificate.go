package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func CertificateFactory(certificateHandshake Handshake) []byte {
	certificateEntry := ParseCertificate(certificateHandshake)
	certs := VerifyCertificataionX509(certificateEntry.CertificateList)
	fmt.Println("certificate verified")
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

	return certsEntry
}

func VerifyCertificataionOCSP(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return errors.New("issuer certificate is missing")
	}
	cert := certs[0]
	issuer := certs[1]
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return err
	}
	ocspServer := cert.OCSPServer[0]
	req, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewReader(ocspRequest))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	const ocspGetRequestThreshold = 255
	base64EncodedRequest := base64.StdEncoding.EncodeToString(ocspRequest)
	if len(base64EncodedRequest) < ocspGetRequestThreshold {
		var err error
		base64EncodedRequest := base64.StdEncoding.EncodeToString(ocspRequest)
		req, err = http.NewRequest(http.MethodGet, ocspServer+"/"+base64EncodedRequest, http.NoBody)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/ocsp-response")
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	ocspResponse, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		var responseErr ocsp.ResponseError
		if errors.As(err, &responseErr) {
			return fmt.Errorf("ocsp status: %s", responseErr.Status.String())
		}
		return err
	}

	if ocspResponse.Certificate != nil {
		if ocspResponse.Certificate.IsCA {
			return errors.New("ocsp response certificate should be end-entity certificate")
		}
		if ocspResponse.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return errors.New("ocsp response certificate has no digital signature key usage")
		}
		var oidExtensionNameOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

		if !hasExtension(ocspResponse.Certificate.Extensions, oidExtensionNameOCSPNoCheck) {
			return errors.New("no id-pkix-ocsp-nocheck extension")
		}
		pool := x509.NewCertPool()
		pool.AddCert(issuer)
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		}
		if _, err := ocspResponse.Certificate.Verify(opts); err != nil {
			return err
		}
	}

	now := time.Now()
	if ocspResponse.ThisUpdate.After(now) {
		return fmt.Errorf("ocsp response thisUpdate(%s) is in the future", ocspResponse.ThisUpdate.Format(time.RFC3339))
	}
	if !ocspResponse.NextUpdate.IsZero() && ocspResponse.NextUpdate.Before(now) {
		return fmt.Errorf("ocsp response nextUpdate(%s) is in the past", ocspResponse.NextUpdate.Format(time.RFC3339))
	}
	if ocspResponse.Status != ocsp.Good {
		return errors.New("ocsp response status is not good")
	}
	fmt.Println("ocsp verified")
	return nil
}

func hasExtension(ext []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, ext := range ext {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}
