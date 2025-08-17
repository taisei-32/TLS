package tls

import (
	"fmt"

	"github.com/taisei-32/TLS/internal/tls/common"
)

func RecordFactory(recordBytes []byte) {
	record := ParseRecord(recordBytes)
	switch record.ContentType {
	case byte(common.Invalid):
		fmt.Println("Invalid")
	case byte(common.ChangeCipherSpec):
		fmt.Println("ChangeCipherSpec")
	case byte(common.Alert):
		fmt.Println("Alert")
	case byte(common.Handshake):
		fmt.Println("Handshake")
	case byte(common.Application):
		fmt.Println("Application")
	}
}
