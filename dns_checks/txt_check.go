package dns_checks

import (
	"net"
)

func TxtCheck(domain string) []string {
	txtData, _ := net.LookupTXT(domain)
	dmarcData, _ := net.LookupTXT("_dmarc." + domain)
	txtData = append(txtData, dmarcData...)
	dkimData, _ := net.LookupTXT("default._domainkey." + domain)
	txtData = append(txtData, dkimData...)
	return txtData
}
