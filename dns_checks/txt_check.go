package dns_checks

import (
	"net"
)

func TxtCheck(domain string) []string {
	txtData, _ := net.LookupTXT(domain)
	// if err != nil {
	// 	fmt.Printf("TXT Record not found %v\n", err)
	// }
	return txtData
}
