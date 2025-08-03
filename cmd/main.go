package main

import (
	"crypto/ecdh"
	"fmt"
	"log"

	"github.com/taisei-32/TLS/internal/tcp"
	"github.com/taisei-32/TLS/internal/tls"
)

type Key struct {
	privateKey ecdh.PrivateKey
	publicKey  ecdh.PublicKey
	hash       string
	// binder_key
	// client_early_traffic_secret
	// early_exporter_master_secret
	// server_handshake_traffic_secret
	// client_handshake_traffic_secret
	// server_application_traffic_secret_N
	// client_application_traffic_secret_N
	// resumption_master_secret
}

func main() {
	private, public, err := tls.GenEcdhX25519()
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}

	Key := Key{
		privateKey: *private,
		publicKey:  *public,
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

	clientHelloStr := tls.ClientHelloRecordFactory(servername, &Key.publicKey)

	clientHello := tls.ToClientRecordByteArr(clientHelloStr)

	fmt.Println("ClientHello:", clientHello)

	_, err = conn.Write(clientHello)
	if err != nil {
		panic("Failed to send ClientHello: " + err.Error())
	}

	fmt.Println("ClientHello sent successfully")

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		panic("Failed to read response: " + err.Error())
	}

	fmt.Println("Received response length:", n)
	fmt.Println("Received response:", response[:n])

	length := response[4]
	result, _ := tls.ServerHelloFactory(response[5 : 5+length])
	keyshare := result.TLSExtensions[0].Value.(map[string]interface{})
	parseCipherSuite := tls.ParseCipherSuite(result.CipherSuite)
	Key.hash = parseCipherSuite.Hash

	fmt.Println("ServerHello parsed successfully")
	fmt.Println("ServerHello Length:", length)
	fmt.Println("ServerHello Version:", result.Version)
	fmt.Println("ServerHello Random:", result.Random)
	fmt.Println("ServerHello SessionID Length:", result.SessionIDLength)
	fmt.Println("ServerHello SessionID:", result.SessionID)
	fmt.Println("ServerHello CipherSuite:", result.CipherSuite)
	fmt.Println("ServerHello Extensions:", keyshare)
	fmt.Println("ServerHello Extensions:", keyshare["KeyExchange"])

	serverHelloPubKey, err := ecdh.X25519().NewPublicKey(keyshare["KeyExchange"].([]byte))
	if err != nil {
		log.Fatal("failed to parse peer public key:", err)
	}

	sharekey, err := tls.GenerateSharedSecret(&Key.privateKey, serverHelloPubKey)
	if err != nil {
		panic("Failed to generate ECDH key pair: " + err.Error())
	}
}
