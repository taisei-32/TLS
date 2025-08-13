package tls

func GenChangeCipherSpec() []byte {
	return []byte{14, 03, 03, 00, 01, 01}
}
