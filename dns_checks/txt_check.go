package dns_checks

import (
	"net"
	"strings"
)

func TxtCheck(domain string) []string {
	if strings.Contains(domain, "mail") {
		domain = strings.Replace(domain, "mail.", "", 1)
		if len(strings.Split(domain, ".")) > 2 {
			domain = strings.Join(strings.Split(domain, ".")[1:], ".")
		}
	}
	txtData, _ := net.LookupTXT(domain)
	dmarcData, _ := net.LookupTXT("_dmarc." + domain)
	txtData = append(txtData, dmarcData...)
	dkimData, _ := net.LookupTXT("default._domainkey." + domain)
	txtData = append(txtData, dkimData...)
	return txtData
}
