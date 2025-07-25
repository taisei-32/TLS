package internal

type ServerHello struct {
	HandshakeType     []byte
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
 */
func ParseServerHello(packet []byte) (ServerHello, error) {
	serverHello := ServerHello{
		HandshakeType:     packet[0:1],
		Length:            packet[1:4],
		Version:           packet[4:6],
		Random:            packet[6:38],
		SessionIDLength:   packet[38:39],
		SessionID:         packet[39:71],
		CipherSuite:       packet[71:73],
		CompressionMethod: packet[73:74],
		ExtensionLength:   packet[74:76],
	}
	// supported_versions
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[76:78],
		Length: packet[78:80],
		Value:  packet[80:82],
	})

	//key_share
	serverHello.TLSExtensions = append(serverHello.TLSExtensions, TLSExtensions{
		Type:   packet[82:84],
		Length: packet[84:86],
		Value: map[string]interface{}{
			"Group":             packet[86:88],
			"KeyExchangeLength": packet[88:90],
			"KeyExchange":       packet[90:122],
		},
	})

	return serverHello, nil
}
