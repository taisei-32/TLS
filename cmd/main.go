package main

import (
	"crypto/ecdh"
	"fmt"

	"github.com/taisei-32/TLS/internal/tcp"
	"github.com/taisei-32/TLS/internal/tls"
)

func main() {
	private, public, err := tls.GenEcdhX25519()
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}

	clientkeyshare := tls.Key{
		PrivateKey: private,
		PublicKey:  public,
	}

	// conn, err := tcp.Conn("portfolio.malsuke.dev:443")
	servername := "www.itotai.com"
	url := servername + ":443"
	fmt.Println("hostname: ", url)
	conn, err := tcp.Conn(url)
	fmt.Println("Connecting to example.com:443")

	if err != nil {
		panic("Failed to connect: " + err.Error())
	}
	defer conn.Close()

	clientHelloRaw := tls.ToClientHandshakeByteArr(tls.ClientHandshakeFactory(servername, clientkeyshare.PublicKey))
	clientRecordRaw := tls.ClientHelloRecordFactory(clientHelloRaw)

	clientHello := tls.ToClientRecordByteArr(clientRecordRaw)

	fmt.Println("ClientHello:", clientHello)

	_, err = conn.Write(clientHello)
	if err != nil {
		panic("Failed to send ClientHello: " + err.Error())
	}

	fmt.Println("ClientHello sent successfully")

	response, responseLength := tls.GetResponse(conn)

	// fmt.Println("length:", responseLength)
	// fmt.Println("Totale Received response:", response[:responseLength])

	// response1 := make([]byte, 4096)
	// n, err := conn.Read(response1)
	// if err != nil {
	// 	panic("Failed to read response: " + err.Error())
	// }

	// fmt.Println("Received response length:", n)
	// fmt.Println("Received response:", response[:responseLength])

	length := response[4]
	fmt.Println("response", response[4])
	serverHello, _ := tls.ServerHelloFactory(response[5 : 5+length])
	// serverHelloRaw := tls.ToSeverHelloByteArr(serverHello)
	serverHelloRaw := response[5 : 5+length]
	severhellokeyshare := serverHello.TLSExtensions[0].Value.(map[string]interface{})
	parseCipherSuite := tls.ParseCipherSuite(serverHello.CipherSuite)

	clientkeyshare.HashAlgorithm = parseCipherSuite.Hash

	encryptedMessage := response[5+length+6 : responseLength]

	// fmt.Println("ServerHello parsed successfully")
	// fmt.Println("ServerHello Length:", length)
	// fmt.Println("ServerHello Version:", serverHello.Version)
	// fmt.Println("ServerHello Random:", serverHello.Random)
	// fmt.Println("ServerHello SessionID Length:", serverHello.SessionIDLength)
	// fmt.Println("ServerHello SessionID:", serverHello.SessionID)
	fmt.Println("ServerHello CipherSuite:", serverHello.CipherSuite)
	// fmt.Println("ServerHello CipherSuite:", serverHello.TLSExtensions)
	// fmt.Println("ServerHello Extensions:", severhellokeyshare)
	// fmt.Println("ServerHello Extensions:", severhellokeyshare["KeyExchange"])
	// fmt.Println("ServerHello Extensions:", serverHello.TLSExtensions[1])

	clientkeyshare.ServerHelloKey, err = ecdh.X25519().NewPublicKey(severhellokeyshare["KeyExchange"].([]byte))
	if err != nil {
		panic("Failed to regen ServerKey")
	}

	clientkeyshare.SharedKey, err = tls.GenerateSharedSecret(clientkeyshare.PrivateKey, clientkeyshare.ServerHelloKey)
	if err != nil {
		panic("Failed to gen sharedKey")
	}
	// fmt.Println("hash:", parseCipherSuite.Hash)

	clientsecretkey, hashFunc := tls.KeyScheduleFactory(clientkeyshare.HashAlgorithm, clientHelloRaw, serverHelloRaw, clientkeyshare.SharedKey)

	// fmt.Println("clientSecretState:", clientsecretkey)
	// fmt.Println("encryptedMessage:", encryptedMessage)

	rawtext, err := tls.DecryptHandshakeFactory(encryptedMessage, clientsecretkey)
	// fmt.Println("plaintext:", rawtext)

	// handshakeをみて分ける関数が欲しい
	encryptedextensions, cetificate, certificateverify, _ := tls.ParseRawData(rawtext)
	certData := tls.CertificateFactory(cetificate)

	transscipthash := tls.GenTransScriptHash1(clientHelloRaw, serverHelloRaw, encryptedextensions, cetificate, hashFunc)

	tls.VerifyCertificateVerifyFactory(certificateverify, transscipthash, clientkeyshare.HashAlgorithm, certData)
}
