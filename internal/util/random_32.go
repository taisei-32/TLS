package util

import (
	"crypto/rand"
	"io"
)

func Random32Bytes() [32]byte {
	randBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, randBytes)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return [32]byte(randBytes)
}
