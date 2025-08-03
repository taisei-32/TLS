package tls

import "strings"

type CipherSuite struct {
	Algorithm string
	KeyLength string
	Mode      string
	Hash      string
}

func ParseCipherSuite(cipherSuite []byte) CipherSuite {
	parts := strings.Split(string(cipherSuite), "_")
	return CipherSuite{
		Algorithm: parts[0],
		KeyLength: parts[1],
		Mode:      parts[2],
		Hash:      parts[3],
	}
}
