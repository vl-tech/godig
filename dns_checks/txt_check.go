package dns_checks

import (
	"net"
)

func TxtCheck(domain string) []string {
	txtData, _ := net.LookupTXT(domain)
	return txtData
}
