package main

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tcp"
	"github.com/taisei-32/TLS/internal/tls"
)

func main() {
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

	clientHelloStr := tls.ClientHelloRecordFactory(servername)

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

	fmt.Println("ServerHello parsed successfully")
	fmt.Println("ServerHello Length:", length)
	fmt.Println("ServerHello Version:", result.Version)
	fmt.Println("ServerHello Random:", result.Random)
	fmt.Println("ServerHello SessionID Length:", result.SessionIDLength)
	fmt.Println("ServerHello SessionID:", result.SessionID)
	fmt.Println("ServerHello CipherSuite:", result.CipherSuite)

	// keyshare := tls.GenerateSharedSecret(clientHelloStr.Payl)
}
