package dns_checks

import (
	"fmt"
	"net"
)

func NsLookup(domain string) []string {

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
