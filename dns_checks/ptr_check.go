package dns_checks
import (
	"net"
	"fmt"
)
func ReverseLookup(ipAddress string) string {

	ip_data, _ := net.LookupAddr(ipAddress)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error:  %s\n", err)

	// }

	for _, ip := range ip_data {
		return ip
	}

	if len(ip_data) < 1 {
		return "No PTR Found"
	} else {
		return fmt.Sprintf("IP Data%s\n", ip_data)
	}

}
