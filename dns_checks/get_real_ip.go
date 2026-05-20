package dns_checks
import (
	"net"
	"fmt"
	"os"
)
// GetRealIp resolves a CNAME domain to its first IP address, used to bypass Cloudflare proxying
func GetRealIp(cNameDomain string) string {
	ips, err := net.LookupIP(cNameDomain)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}
