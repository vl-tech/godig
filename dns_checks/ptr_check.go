package dns_checks

import (
	"fmt"
	"net"
)

func ReverseLookup(ipAddress string) string {

	ip_data, _ := net.LookupAddr(ipAddress)

	for _, ip := range ip_data {
		return ip
	}

	if len(ip_data) < 1 {
		return "No PTR Found"
	} else {
		return fmt.Sprintf("IP Data%s\n", ip_data)
	}

}
