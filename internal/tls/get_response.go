package tls

import (
	"io"
	"net"
)

func GetResponse(conn net.Conn) ([]byte, int) {
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

		// fmt.Println("Received response:", tmpResponse[:n])
		response = append(response, tmpResponse[:n]...)
		responseLength += n
	}
	return response[:responseLength], responseLength
}
