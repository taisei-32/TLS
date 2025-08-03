package tls

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

type HkdfLabel struct {
	length  uint
	label   string
	context []byte
}

func HKDFExtract(secret, salt []byte, hashFunc func() hash.Hash) []byte {
	// hash := getHash(hashAlgorithm)
	return hkdf.Extract(hashFunc, secret, salt)
}

func DeriveSecret(secret []byte, label string, transcriptHash []byte, hashFunc func() hash.Hash) []byte {
	// hash := getHash(hashAlgorithm)
	return HKDFExpandLabel(secret, label, transcriptHash, hashFunc)
}

func HKDFExpand(secret []byte, label []byte, length int, hashFunc func() hash.Hash) []byte {
	expand := hkdf.Expand(hashFunc, secret, label)
	expand_byte := make([]byte, length)
	_, err := io.ReadFull(expand, expand_byte)
	if err != nil {
		panic("Failed expand")
	}

	return expand_byte
}

func HKDFExpandLabel(secret []byte, label string, context []byte, hashFunc func() hash.Hash) []byte {
	hkdflabel := HkdfLabel{
		length:  uint(hashFunc().Size()),
		label:   "tls13" + label,
		context: context,
	}

	return HKDFExpand(secret, ToHkdfLabelByteArr(hkdflabel), int(hkdflabel.length), hashFunc)
}
