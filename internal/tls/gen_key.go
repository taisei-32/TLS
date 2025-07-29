package tls

import (
	"crypto/ecdh"
	"crypto/rand"
)

func GenEcdhX25519() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PublicKey()
	return priv, pub, nil
}

func GenerateSharedSecret(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}
