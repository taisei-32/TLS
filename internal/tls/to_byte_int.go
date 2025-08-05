package tls

func BytesToInt24(ext [3]byte) int {
	return int(ext[0])<<16 | int(ext[1])<<8 | int(ext[2])
}

func BytesToint8(ext byte) int {
	return int(ext)
}
