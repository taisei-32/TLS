package internal

type ServerHello struct {
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
func ParseServerHello(packet []byte) (ServerHello, error) {
	serverHello := ServerHello{
		Version:           packet[0:2],
		Random:            packet[2:34],
		SessionIDLength:   packet[34:35],
		SessionID:         packet[35:67],
		CipherSuite:       packet[67:69],
		CompressionMethod: packet[69:70],
		ExtensionLength:   packet[70:72],
	}
	// supported_versions
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[72:74],
		Length: packet[74:76],
		Value:  packet[76:78],
	})

	//key_share
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[78:80],
		Length: packet[80:82],
		Value: map[string]interface{}{
			"Group":             packet[82:84],
			"KeyExchangeLength": packet[84:86],
			"KeyExchange":       packet[86:],
		},
	})

	return serverHello, nil
}
