package tls

import "hash"

type SecretKey struct {
	EarlySecret     []byte
	HandshakeSecret []byte
	MasterSecret    []byte
	HashAlgorithm   string
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

	SecretState := HKDFExpandLabel(earlySecret, "derived", nil, hashFunc)
	handshakeSecret := HKDFExtract(hashFunc, SecretState, sharedSecret)

	clientHandshakeSecret := DeriveSecret(handshakeSecret, "c hs traffic", transcriptHash, hashFunc)
	serverHandshakeSecret := DeriveSecret(handshakeSecret, "s hs traffic", transcriptHash, hashFunc)

	return SecretKey{
		EarlySecret:                  earlySecret,
		HandshakeSecret:              handshakeSecret,
		ClientHandshakeTrafficSecret: clientHandshakeSecret,
		ServerHandshakeTrafficSecret: serverHandshakeSecret,
	}
}
