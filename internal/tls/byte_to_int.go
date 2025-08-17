package tls

import "encoding/binary"

func BytesToInt24(ext [3]byte) int {
	return int(ext[0])<<16 | int(ext[1])<<8 | int(ext[2])
}

func BytesToUint16(ext []byte) uint16 {
	return binary.BigEndian.Uint16(ext)
}

func BytesToint8(ext byte) int {
	return int(ext)
}
