package dns_checks

import (
	"fmt"
	"net"
	"strings"
)

// NsLookup returns the NS records for a domain, stripping mail. prefix if present
func NsLookup(domain string) []string {
	if strings.Contains(domain, "mail") {
		domain = strings.Replace(domain, "mail.", "", 1)
		if len(strings.Split(domain, ".")) > 2 {
			domain = strings.Join(strings.Split(domain, ".")[1:], ".")
		}
	}
	listNS := []string{}
	nsData, err := net.LookupNS(domain)
	if err != nil {
		fmt.Printf("NS Error %s\n", err)
	}
	for _, nsRecord := range nsData {
		listNS = append(listNS, nsRecord.Host)
	}
	return listNS
}
