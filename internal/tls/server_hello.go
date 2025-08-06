package tls

type ServerHello struct {
	ContentType       []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionIDLength   byte
	SessionID         []byte
	CipherSuite       []byte
	CompressionMethod byte
	ExtensionLength   []byte
	TLSExtensions     []TLSExtensions
}

type TLSExtensions struct {
	Type   []byte
	Length []byte
	Value  interface{}
}

/**
 * TODO: 仮にサーバー側の送信するバイト列が誤っていた場合にクライアントはどう検知するのか調べる
 * TODO: SessionIDのLengthに応じてoffsetを付ける必要があるが、ここでは一旦32バイトとして処理を進める
 */
func ServerHelloFactory(packet []byte) (ServerHello, error) {
	serverHello, extension := ParseServerHello(packet)
	tlsExtensions := ParseServerHelloExtension(extension)
	serverHello.TLSExtensions = tlsExtensions
	return serverHello, nil
}
