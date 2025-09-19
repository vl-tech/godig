package dns_checks

import (
	"github.com/fatih/color"
	"net"
	"os"
)

func DomainIP(domain string) string {
	e := color.New(color.FgRed, color.Bold)
	ips, err := net.LookupIP(domain)

	if err != nil {
		e.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}
