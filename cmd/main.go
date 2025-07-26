package main

import (
	"fmt"

	"github.com/taisei-32/TLS/internal"
	"github.com/taisei-32/TLS/internal/tcp"
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

	clientHello := internal.ToClientRecordByteArr(internal.ClientHelloRecordFactory(servername))

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

	fmt.Println("Received response:", response[:n])
}
