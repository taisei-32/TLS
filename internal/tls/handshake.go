package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

func HandshakeFactory(handshakeBytes []byte) {
	handshake := ParseHandshake(handshakeBytes)
	switch handshake.HandshakeType {
	case byte(common.ClientHello):
		fmt.Println("ClientHello")
	case byte(common.ServerHello):
		fmt.Println("ServerHell")
	case byte(common.EndOfEarlyData):
		fmt.Println("EndOfEarlyData")
	case byte(common.EncryptedExtensions):
		fmt.Println("EncryptedExtensions")
	case byte(common.CertificateRequest):
		fmt.Println("CertificateRequest")
	case byte(common.Certificate):
		fmt.Println("Certificate")
	case byte(common.CertificateVerify):
		fmt.Println("CertificateVerify")
	case byte(common.Finished):
		fmt.Println("Finished ")
	case byte(common.KeyUpdate):
		fmt.Println("KeyUpdate ")
	}
}
