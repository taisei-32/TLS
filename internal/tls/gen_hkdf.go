package tls

import (
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

type HkdfLabel struct {
	Length        []byte
	LabelLength   byte
	Label         []byte
	ContextLength byte
	Context       []byte
}

func HKDFExtract(hashFunc func() hash.Hash, salt []byte, secret []byte) []byte {
	return hkdf.Extract(hashFunc, secret, salt)
}

func DeriveSecret(secret []byte, label string, transcriptHash []byte, hashFunc func() hash.Hash) []byte {
	return HKDFExpandLabel(secret, label, transcriptHash, hashFunc().Size(), hashFunc)
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

func HKDFExpandLabel(secret []byte, label string, transcriptHash []byte, length int, hashFunc func() hash.Hash) []byte {
	labelData := []byte("tls13 " + label)
	hkdflabel := HkdfLabel{
		Length:        Uint16ToBytes(uint16((length))),
		LabelLength:   byte(len(labelData)),
		Label:         labelData,
		ContextLength: byte(len(transcriptHash)),
		Context:       transcriptHash,
	}

	a := ToHkdfLabelByteArr(hkdflabel)

	return HKDFExpand(secret, a, length, hashFunc)
}
