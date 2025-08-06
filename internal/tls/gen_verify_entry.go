package tls

func GenCertificateEntry(certificateEntry []byte) []CertificateEntry {
	var certificateList []CertificateEntry
	remain := certificateEntry
	for len(remain) > 0 {
		var entry CertificateEntry
		entry, remain = ParseCertificateEntry(remain)
		certificateList = append(certificateList, entry)
	}
	// var entry CertificateEntry
	// entry, remain = ParseCertificateEntry(remain)
	// certificateList = append(certificateList, entry)
	return certificateList
}
