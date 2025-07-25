package tcp_test

import (
	"testing"

	"github.com/taisei-32/TLS/internal/tcp"
)

func TestConn(t *testing.T) {
	t.Run("example.comへtcp接続を行う", func(t *testing.T) {
		conn, err := tcp.Conn("example.com:80")
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		if conn == nil {
			t.Fatalf("connection is nil")
		}
		// _, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		// buf := make([]byte, 4096)
		// _, err = conn.Read(buf)
		// if err != nil {
		// 	t.Fatalf("failed to read: %v", err)
		// }

		// t.Fatalf("Received response: %s", string(buf))
		defer conn.Close()
	})
}
