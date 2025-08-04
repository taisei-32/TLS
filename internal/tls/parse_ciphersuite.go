package tls

type CipherSuite struct {
	Algorithm string
	KeyLength string
	Mode      string
	Hash      string
}

func ParseCipherSuite(cipherSuite []byte) CipherSuite {
	// if cipherSuite[1] == byte{1} {
	// 	return
	// }
	// parts := strings.Split(string(cipherSuite), "_")
	return CipherSuite{
		Algorithm: "AES",
		KeyLength: "128",
		Mode:      "GCM",
		Hash:      "SHA256",
	}
}
