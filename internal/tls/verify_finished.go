package tls

import (
	"bytes"
	"fmt"
	"hash"
)

func VerifyFinishedFactory(finised Handshake, transcriptHash []byte, finishedKey []byte, hashFunc func() hash.Hash) {
	hmac := GenHmac(hashFunc, finishedKey, transcriptHash)
	// fmt.Println("hmac:", hmac)
	// fmt.Println("finished:", finised.msg)
	if bytes.Equal(hmac, finised.Msg) {
		fmt.Println("finished was verified")
	} else {
		panic("finished was not verified")
	}
}
