package util

import "encoding/binary"

func Uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

func Uint24ToBytes(n uint32) [3]byte {
	var buf [3]byte
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	copy(buf[:], b[1:]) // 4バイトのうち下位3バイトをコピー
	return buf
}
