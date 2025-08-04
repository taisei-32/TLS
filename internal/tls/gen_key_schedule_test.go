package tls_test

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/taisei-32/TLS/internal/tls"
	"golang.org/x/crypto/curve25519"
)

// const testData = []byte

const clienthello = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
const serverhello = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

func TestGenKeySchedule(t *testing.T) {
	t.Run("鍵スケジュールの生成が正しい", func(t *testing.T) {
		clientHelloRaw, _ := hex.DecodeString(clienthello)
		serverHelloRaw, _ := hex.DecodeString(serverhello)

		clientPrivateKey, err := hex.DecodeString("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
		if err != nil {
			log.Fatal(err)
		}
		serverPublicKey, err := hex.DecodeString("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
		if err != nil {
			log.Fatal(err)
		}

		sharedkey, _ := curve25519.X25519(clientPrivateKey, serverPublicKey)

		key := tls.KeyScheduleFactory("SHA256", clientHelloRaw, serverHelloRaw, sharedkey)
		// if err != nil {
		// 	t.Fatalf("ランダムな値の生成に失敗: %v", err)
		// }
		// if len(randomBytes) != 32 {
		// 	t.Errorf("期待される長さは32バイトですが、実際の長さは%dバイトです", len(randomBytes))
		// }
		// t.Logf("生成されたランダムな値: %x", randomBytes)
		t.Logf("ClientHandshakeTrafficSecret: %x", key.ClientHandshakeTrafficSecret)
		t.Logf("ServerHandshakeTrafficSecret: %x", key.ServerHandshakeTrafficSecret)
	})
}
