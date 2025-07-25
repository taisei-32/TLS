package internal

import "github.com/taisei-32/TLS/internal/util"

// 2. key_share拡張を構築します。
// 構造:
// - 拡張タイプ (2バイト: 0x0033)
// - 拡張データ長 (2バイト)
// - クライアント鍵共有リスト長 (2バイト)
// - 鍵共有エントリ (x25519):
//   - 名前付きグループ (2バイト: 0x001d for x25519)
//   - 鍵交換データ長 (2バイト: 32 bytes for x25519)
//   - 鍵交換データ (32バイト: 公開鍵)

func CmpExtension(publickey []byte) []byte {
	const KeyShareExtType = 0x0033
	const KeyXGroup = 0x001D

	PubLength := len(publickey)
	KeyEntryLength := 2 + 2 + PubLength
	KeyDataLength := KeyEntryLength
	ExtDataLength := 2 + KeyDataLength

	ExtData := []byte{}
	ExtData = append(ExtData, util.Uint16ToBytes(uint16(ExtDataLength))...)
	ExtData = append(ExtData, util.Uint16ToBytes(KeyShareExtType)...)
	ExtData = append(ExtData, util.Uint16ToBytes(uint16(KeyDataLength))...)
	ExtData = append(ExtData, util.Uint16ToBytes(uint16(KeyEntryLength))...)
	ExtData = append(ExtData, util.Uint16ToBytes(KeyXGroup)...)
	ExtData = append(ExtData, util.Uint16ToBytes(uint16(PubLength))...)
	ExtData = append(ExtData, publickey...)

	return ExtData
}
