package tls

import "encoding/binary"

// --- バイト変換ヘルパー関数 (これはそのまま使います) ---

func Uint16ToBytes(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

func Uint24ToBytes(n uint32) []byte {
	b := make([]byte, 3)
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
	return b
}

// --- 各構造体のToBytes()メソッド ---

func (l HkdfLabel) ToBytes() []byte {
	var arr []byte
	arr = append(arr, Uint16ToBytes(l.Length)...)
	arr = append(arr, byte(len(l.Label)))
	arr = append(arr, l.Label...)
	arr = append(arr, byte(len(l.Context)))
	arr = append(arr, l.Context...)
	return arr
}

func (e Extension) ToBytes() []byte {
	var arr []byte
	arr = append(arr, Uint16ToBytes(e.Type)...)
	arr = append(arr, Uint16ToBytes(uint16(len(e.Data)))...)
	arr = append(arr, e.Data...)
	return arr
}

func (ch ClientHello) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.LegacyVersion[:]...)
	arr = append(arr, ch.Random[:]...)

	arr = append(arr, byte(len(ch.LegacySessionID))) // Session ID length (32)
	arr = append(arr, ch.LegacySessionID[:]...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.CipherSuites)))...)
	arr = append(arr, ch.CipherSuites...)

	arr = append(arr, byte(len(ch.LegacyCompressionMethods)))
	arr = append(arr, ch.LegacyCompressionMethods...)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

func (ch ServerHello) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.ContentType...)
	arr = append(arr, ch.Length...)

	arr = append(arr, ch.Version...) // Session ID length (32)
	arr = append(arr, ch.Random...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.SessionID)))...)
	arr = append(arr, ch.SessionID...)

	arr = append(arr, ch.CipherSuite...)
	arr = append(arr, ch.CompressionMethod)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

func (ch EncryptedExtensions) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.LegacyVersion[:]...)
	arr = append(arr, ch.Random[:]...)

	arr = append(arr, byte(len(ch.LegacySessionID))) // Session ID length (32)
	arr = append(arr, ch.LegacySessionID[:]...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.CipherSuites)))...)
	arr = append(arr, ch.CipherSuites...)

	arr = append(arr, byte(len(ch.LegacyCompressionMethods)))
	arr = append(arr, ch.LegacyCompressionMethods...)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

func (ch CertificateMsg) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.LegacyVersion[:]...)
	arr = append(arr, ch.Random[:]...)

	arr = append(arr, byte(len(ch.LegacySessionID))) // Session ID length (32)
	arr = append(arr, ch.LegacySessionID[:]...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.CipherSuites)))...)
	arr = append(arr, ch.CipherSuites...)

	arr = append(arr, byte(len(ch.LegacyCompressionMethods)))
	arr = append(arr, ch.LegacyCompressionMethods...)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

func (ch CertificateVerifyMsg) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.LegacyVersion[:]...)
	arr = append(arr, ch.Random[:]...)

	arr = append(arr, byte(len(ch.LegacySessionID))) // Session ID length (32)
	arr = append(arr, ch.LegacySessionID[:]...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.CipherSuites)))...)
	arr = append(arr, ch.CipherSuites...)

	arr = append(arr, byte(len(ch.LegacyCompressionMethods)))
	arr = append(arr, ch.LegacyCompressionMethods...)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

func (ch Finished) ToBytes() []byte {
	var arr []byte
	arr = append(arr, ch.LegacyVersion[:]...)
	arr = append(arr, ch.Random[:]...)

	arr = append(arr, byte(len(ch.LegacySessionID))) // Session ID length (32)
	arr = append(arr, ch.LegacySessionID[:]...)

	arr = append(arr, Uint16ToBytes(uint16(len(ch.CipherSuites)))...)
	arr = append(arr, ch.CipherSuites...)

	arr = append(arr, byte(len(ch.LegacyCompressionMethods)))
	arr = append(arr, ch.LegacyCompressionMethods...)

	// Extensionsをバイト列に変換
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.ToBytes()...)
	}
	arr = append(arr, Uint16ToBytes(uint16(len(extensionsBytes)))...)
	arr = append(arr, extensionsBytes...)

	return arr
}

// (ServerHello, Certificateなども同様にToBytes()メソッドを実装)

// Handshake構造体自身のToBytes()メソッド（これがディスパッチャの役割を果たす）
func (h Handshake) ToBytes() []byte {
	var bodyBytes []byte

	// タイプスイッチでBodyの中身の「具体的な型」を判別し、その型のToBytes()を呼び出す
	switch body := h.Body.(type) {
	case ClientHello:
		bodyBytes = body.ToBytes()
	case ServerHello:
		// bodyBytes = body.ToBytes() // ServerHelloも同様に実装
	// ... 他のハンドシェイクメッセージも同様 ...
	default:
		panic("unsupported handshake message type for serialization")
	}

	// Handshakeヘッダーを作成
	var result []byte
	result = append(result, h.HandshakeType)
	result = append(result, Uint24ToBytes(uint32(len(bodyBytes)))...)
	result = append(result, bodyBytes...)

	return result
}

// Record構造体自身のToBytes()メソッド
func (r Record) ToBytes() []byte {
	var arr []byte
	arr = append(arr, r.ContentType)
	arr = append(arr, r.LegacyVersion[:]...)
	// RecordのLengthはPayloadの長さ
	arr = append(arr, Uint16ToBytes(uint16(len(r.Payload)))...)
	arr = append(arr, r.Payload...)
	return arr
}
