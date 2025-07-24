package tcp

import (
	"log/slog"
	"net"
)

func Conn(hostPort string) (*net.TCPConn, error) {
	serverTcpAddr, _ := net.ResolveTCPAddr("tcp", hostPort)

	conn, err := net.DialTCP("tcp", nil, serverTcpAddr)
	if err != nil {
		slog.Error("Failed to connect to server", "hostPort", hostPort, "error", err)
		return nil, err
	}
	return conn, nil
}
