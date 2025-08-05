package main

import (
	"crypto/ecdh"
	"fmt"
	"io"
	"log"

	"github.com/taisei-32/TLS/internal/tcp"
	"github.com/taisei-32/TLS/internal/tls"
)

type KeyShare struct {
	privateKey     *ecdh.PrivateKey
	publicKey      *ecdh.PublicKey
	serverHelloKey *ecdh.PublicKey
	sharedKey      []byte
}

func main() {
	private, public, err := tls.GenEcdhX25519()
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}

	clientkeyshare := KeyShare{
		privateKey: private,
		publicKey:  public,
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

	clientHelloRaw := tls.ToClientHandshakeByteArr(tls.ClientHandshakeFactory(servername, clientkeyshare.publicKey))
	clientRecordRaw := tls.ClientHelloRecordFactory(clientHelloRaw)

	clientHello := tls.ToClientRecordByteArr(clientRecordRaw)

	fmt.Println("ClientHello:", clientHello)

	_, err = conn.Write(clientHello)
	if err != nil {
		panic("Failed to send ClientHello: " + err.Error())
	}

	fmt.Println("ClientHello sent successfully")

	var response []byte
	tmpResponse := make([]byte, 8192)
	var responseLength int

	for {
		n, err := conn.Read(tmpResponse)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic("Failed to read response: " + err.Error())
		}

		fmt.Println("Received response:", tmpResponse[:n])
		response = append(response, tmpResponse[:n]...)
		responseLength += n
	}
	fmt.Println("length:", responseLength)
	fmt.Println("Totale Received response:", response[:responseLength])

	// response1 := make([]byte, 4096)
	// n, err := conn.Read(response1)
	// if err != nil {
	// 	panic("Failed to read response: " + err.Error())
	// }

	// fmt.Println("Received response length:", n)
	// fmt.Println("Received response:", response1[:n])

	length := response[4]
	serverHello, _ := tls.ServerHelloFactory(response[5 : 5+length])
	serverHelloRaw := tls.ToSeverHelloByteArr(serverHello)
	severhellokeyshare := serverHello.TLSExtensions[0].Value.(map[string]interface{})
	parseCipherSuite := tls.ParseCipherSuite(serverHello.CipherSuite)

	encryptedMessage := response[5+length+6 : responseLength]

	fmt.Println("ServerHello parsed successfully")
	fmt.Println("ServerHello Length:", length)
	fmt.Println("ServerHello Version:", serverHello.Version)
	fmt.Println("ServerHello Random:", serverHello.Random)
	fmt.Println("ServerHello SessionID Length:", serverHello.SessionIDLength)
	fmt.Println("ServerHello SessionID:", serverHello.SessionID)
	fmt.Println("ServerHello CipherSuite:", serverHello.CipherSuite)
	// fmt.Println("ServerHello CipherSuite:", serverHello.TLSExtensions)
	// fmt.Println("ServerHello Extensions:", severhellokeyshare)
	// fmt.Println("ServerHello Extensions:", severhellokeyshare["KeyExchange"])
	// fmt.Println("ServerHello Extensions:", serverHello.TLSExtensions[1])

	clientkeyshare.serverHelloKey, err = ecdh.X25519().NewPublicKey(severhellokeyshare["KeyExchange"].([]byte))
	if err != nil {
		log.Fatal("failed to parse peer public key:", err)
	}

	clientkeyshare.sharedKey, err = tls.GenerateSharedSecret(clientkeyshare.privateKey, clientkeyshare.serverHelloKey)
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}
	fmt.Println("hash:", parseCipherSuite.Hash)

	clientsecretkey := tls.KeyScheduleFactory(parseCipherSuite.Hash, clientHelloRaw, serverHelloRaw, clientkeyshare.sharedKey)

	// fmt.Println("clientSecretState:", clientsecretkey)
	// fmt.Println("encryptedMessage:", encryptedMessage)

	rawtext, err := tls.DecryptHandshakeFactory(encryptedMessage, clientsecretkey)
	fmt.Println("plaintext:", rawtext)

	// handshakeをみて分ける関数が欲しい
	cetificate := tls.ParseRawData(rawtext)
	tls.CertificateFactory(cetificate)

}
