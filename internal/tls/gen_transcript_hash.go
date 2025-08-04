package tls

import "hash"

func GenTransScriptHash(ClientHello []byte, ServerHello []byte, hashFunc func() hash.Hash) []byte {
	transcript := append(ClientHello, ServerHello...)
	hash := hashFunc()
	hash.Write(transcript)
	return hash.Sum(nil)
}
