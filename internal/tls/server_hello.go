package tls

type ServerHello struct {
	ContentType       []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionIDLength   []byte
	SessionID         []byte
	CipherSuite       []byte
	CompressionMethod []byte
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
	serverHello := ServerHello{
		ContentType:       packet[0:1],
		Length:            packet[1:4],
		Version:           packet[4:6],
		Random:            packet[6:38],
		SessionIDLength:   packet[38:39],
		SessionID:         packet[39:71], // 仮に32バイトのSessionIDとする
		CipherSuite:       packet[71:73],
		CompressionMethod: packet[73:74],
		ExtensionLength:   packet[74:76],
	}

	//key_share
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[76:78],
		Length: packet[78:80],
		Value: map[string]interface{}{
			"Group":             packet[80:82],
			"KeyExchangeLength": packet[82:84],
			"KeyExchange":       packet[84:116],
		},
	})

	// supported_versions
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[116:118],
		Length: packet[118:120],
		Value:  packet[120:122],
	})

	return serverHello, nil
}
