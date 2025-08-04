package tls_test

import (
	"testing"

	"github.com/taisei-32/TLS/internal/tls"
)

func TestGenerateRandom32Bytes(t *testing.T) {
	t.Run("32バイトのランダムな値が生成できる", func(t *testing.T) {
		randomBytes := tls.Random32Bytes()
		// if err != nil {
		// 	t.Fatalf("ランダムな値の生成に失敗: %v", err)
		// }
		if len(randomBytes) != 32 {
			t.Errorf("期待される長さは32バイトですが、実際の長さは%dバイトです", len(randomBytes))
		}
		t.Logf("生成されたランダムな値: %x", randomBytes)
	})
}
