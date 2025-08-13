package tls

import (
	"hash"
)

func GenKeySchedule(sharedSecret []byte, hashFunc func() hash.Hash, transcriptHash []byte) SecretKey {
	salt := make([]byte, hashFunc().Size())
	psk := make([]byte, hashFunc().Size())

	earlySecret := HKDFExtract(hashFunc, salt, psk)
	h_nil := hashFunc().Sum(nil)
	EarlySecretState := DeriveSecret(earlySecret, "derived", h_nil, hashFunc)

	handshakeSecret := HKDFExtract(hashFunc, EarlySecretState, sharedSecret)
	clientHandshakeSecret := DeriveSecret(handshakeSecret, "c hs traffic", transcriptHash, hashFunc)
	serverHandshakeSecret := DeriveSecret(handshakeSecret, "s hs traffic", transcriptHash, hashFunc)
	handshakeSecretState := DeriveSecret(handshakeSecret, "derived", h_nil, hashFunc)

	serverfinishedKey := HKDFExpandLabel(serverHandshakeSecret, "finished", []byte(""), hashFunc().Size(), hashFunc)
	clientfinishedKey := HKDFExpandLabel(clientHandshakeSecret, "finished", []byte(""), hashFunc().Size(), hashFunc)

	masterSecret := HKDFExtract(hashFunc, handshakeSecretState, make([]byte, hashFunc().Size()))

	return SecretKey{
		EarlySecret:                  earlySecret,
		HandshakeSecret:              handshakeSecret,
		ClientHandshakeTrafficSecret: clientHandshakeSecret,
		ServerHandshakeTrafficSecret: serverHandshakeSecret,
		Hash:                         hashFunc,
		ServerFinishedKey:            serverfinishedKey,
		ClientFinishedKey:            clientfinishedKey,
		EarySecretState:              EarlySecretState,
		HandshakeSecretState:         handshakeSecretState,
		MasterSecret:                 masterSecret,
	}
}

func GenKeyMasterSecret(masterSecret []byte, hashFunc func() hash.Hash, transcriptHash []byte) ([]byte, []byte) {
	clientApplicationTrafficSecret := DeriveSecret(masterSecret, "c ap traffic", transcriptHash, hashFunc)
	serverApplicationTrafficSecret := DeriveSecret(masterSecret, "s ap traffic", transcriptHash, hashFunc)
	return clientApplicationTrafficSecret, serverApplicationTrafficSecret
}

func KeyScheduleFactory(hashAlgorithm string, clientHelloRaw []byte, serverHelloRaw []byte, sharedkey []byte) (SecretKey, func() hash.Hash) {
	hashFunc := GetHash(hashAlgorithm)
	transscipthash := GenTransScriptHash(clientHelloRaw, serverHelloRaw, hashFunc)
	// fmt.Printf("transscipthash: %x\n", transscipthash)
	keyschedule := GenKeySchedule(sharedkey, hashFunc, transscipthash)
	// if err != nil {
	// 	panic("Failed to generate keyschedule: " + err.Error())
	// }
	keyschedule.Hash = hashFunc

	return keyschedule, hashFunc
}
