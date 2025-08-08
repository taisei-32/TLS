package tls

import "fmt"

/**
 * TODO: 仮にサーバー側の送信するバイト列が誤っていた場合にクライアントはどう検知するのか調べる
 * TODO: SessionIDのLengthに応じてoffsetを付ける必要があるが、ここでは一旦32バイトとして処理を進める
 */
func ServerHelloFactory(packet []byte) (ServerHello, error) {
	fmt.Println("SeverHello", packet)
	serverHello, extension := ParseServerHello(packet)
	tlsExtensions := ParseServerHelloExtension(extension)
	serverHello.TLSExtensions = tlsExtensions
	return serverHello, nil
}
