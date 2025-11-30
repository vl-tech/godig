package dns_checks

import (
	"net"
	"os"

	"github.com/fatih/color"
)

func DomainIP(domain string) string {
	e := color.New(color.FgRed, color.Bold)
	ips, err := net.LookupIP(domain)

	if err != nil {
		// Print error to stderr and return empty string
		// _, _ = e.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
		e.Printf("Unable to parse data:  %s\n", err)
		RdapInfo(domain)
		os.Exit(0)
		return ""

	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}
