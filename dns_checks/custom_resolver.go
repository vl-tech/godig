package dns_checks

import (
	"context"
	"net"
	"time"

	"github.com/fatih/color"
)

// CustomDnsResolver queries A and NS records for a domain using a user-specified DNS server
func CustomDnsResolver(domain string, dnsServer string) {
	y := color.New(color.FgHiGreen, color.Bold)
	m := color.New(color.FgHiMagenta, color.Bold)

	// Custom DNS resolver logic goes here
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Second * 5,
			}
			dns := dnsServer + ":53"
			return dialer.DialContext(ctx, "udp", dns)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m.Printf("Custom DNS Resolver Information:\n\\__\n")
	m.Printf("   %-18s", "DNS Server:")
	y.Printf("%s:53\n", dnsServer)
	m.Printf("   %-18s", "Domain:")
	y.Printf("%s\n", domain)

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		m.Printf("   %-18s", "A Record Error:")
		y.Printf("%v\n", err)
	} else {
		m.Printf("   %-18s", "A Records:")
		y.Printf("\n")
		for _, ip := range ips {
			m.Printf("   %-18s", "")
			y.Printf("%s\n", ip)
		}
	}

	ns, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		m.Printf("   %-18s", "NS Record Error:")
		y.Printf("%v\n", err)
	} else {
		m.Printf("   %-18s", "NS Records:")
		y.Printf("\n")
		for _, nss := range ns {
			m.Printf("   %-18s", "")
			y.Printf("%s\n", nss.Host)
		}
	}
}
