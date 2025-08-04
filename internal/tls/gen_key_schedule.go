package tls

import (
	"hash"
	"log"
)

type SecretKey struct {
	EarlySecret     []byte
	HandshakeSecret []byte
	MasterSecret    []byte
	Hash            func() hash.Hash
	// BinderKey []byte
	// ClientEarlyTrafficSecret []byte
	// CleintEarlyTrafficSecret []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
}

func GenKeySchedule(sharedSecret []byte, hashFunc func() hash.Hash, transcriptHash []byte) SecretKey {
	salt := make([]byte, hashFunc().Size())
	psk := make([]byte, hashFunc().Size())

	earlySecret := HKDFExtract(hashFunc, salt, psk)

	h_nil := hashFunc().Sum(nil)

	SecretState := DeriveSecret(earlySecret, "derived", h_nil, hashFunc)
	handshakeSecret := HKDFExtract(hashFunc, SecretState, sharedSecret)

	clientHandshakeSecret := DeriveSecret(handshakeSecret, "c hs traffic", transcriptHash, hashFunc)
	serverHandshakeSecret := DeriveSecret(handshakeSecret, "s hs traffic", transcriptHash, hashFunc)

	return SecretKey{
		EarlySecret:                  earlySecret,
		HandshakeSecret:              handshakeSecret,
		ClientHandshakeTrafficSecret: clientHandshakeSecret,
		ServerHandshakeTrafficSecret: serverHandshakeSecret,
		Hash:                         hashFunc,
	}
}

func KeyScheduleFactory(hashAlgorithm string, clientHelloRaw []byte, serverHelloRaw []byte, sharedkey []byte) SecretKey {
	hashFunc := GetHash(hashAlgorithm)
	transscipthash := GenTransScriptHash(clientHelloRaw, serverHelloRaw, hashFunc)
	log.Printf("transscipthash: %x\n", transscipthash)
	keyschedule := GenKeySchedule(sharedkey, hashFunc, transscipthash)
	// if err != nil {
	// 	panic("Failed to generate keyschedule: " + err.Error())
	// }
	keyschedule.Hash = hashFunc

	return keyschedule
}
