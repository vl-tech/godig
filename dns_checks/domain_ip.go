package dns_checks

import (
	"net"

	"github.com/fatih/color"
)

// DomainResolves checks if a domain can be resolved without printing errors
// Returns true if domain resolves, false otherwise
func DomainResolves(domain string) bool {
	_, err := net.LookupIP(domain)
	return err == nil
}

func DomainIP(domain string) []string {
	var ipAddresses []string
	e := color.New(color.FgRed, color.Bold)

	ips, err := net.LookupIP(domain)

	if err != nil {
		// Print error to stderr and return empty string
		// _, _ = e.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
		e.Printf("Unable to parse data:  %s\n", err)
		return nil

	}
	for _, ip := range ips {
		ipAddresses = append(ipAddresses, ip.String())
	}
	return ipAddresses
}
