package main

import (
	"domain_analyzer/dns_checks"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/pborman/getopt/v2"
)

var (
	d         = color.New(color.FgHiGreen, color.Bold)
	e         = color.New(color.BgHiMagenta, color.FgYellow, color.Bold)
	t         = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	y         = color.New(color.FgYellow, color.Bold)
	startTime = time.Now()
	r         = color.New(color.FgRed, color.Bold)
)

func main() {
	// Define flags
	help := getopt.BoolLong("help", 'h', "Show help")
	nmapMode := getopt.BoolLong("nmap", 'n', "Run nmap port scan on domain")
	ipInfo := getopt.BoolLong("ip", 'i', "Get IP information")
	singlePort := getopt.IntLong("port", 'p', 0, "Check single port on domain")
	sslCheck := getopt.BoolLong("ssl", 0, "Verify SSL certificate")
	rdapCheck := getopt.BoolLong("rdap", 'r', "Get RDAP/Whois information")
	licenseCheck := getopt.BoolLong("license-check", 'l', "Check cPanel license for IP")
	ptrrecordCheck := getopt.BoolLong("ptr", 'x', "PTR record check ")
	arecordCheck := getopt.Bool('a', "Check A record")

	getopt.Parse()

	// Handle help flag
	if *help || len(os.Args) == 1 {
		dns_checks.HelpFunc()
		return
	}

	args := getopt.Args()

	// Handle nmap mode
	if *nmapMode {
		if len(args) < 1 {
			_, _ = r.Println("Error: -nmap/-n requires a domain argument")
			os.Exit(1)
		}
		domain := dns_checks.CleanDomain(args[0])
		if !dns_checks.DomainResolves(domain) {
			_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
			os.Exit(1)
		}
		ip := dns_checks.DomainIP(domain)
		y.Println("__________________")
		_, _ = t.Println("Checking Server Default ports")
		fmt.Println()
		dns_checks.PortChecker(ip[0])
		os.Exit(0)
	}

	// Handle IP info mode
	if *ipInfo {
		if len(args) < 1 {
			_, _ = r.Println("Error: -ip/-i requires an IP address argument")
			os.Exit(1)
		}
		ip := args[0]
		dns_checks.IpInfo(ip)
		os.Exit(0)
	}

	// Handle single port check
	if *singlePort > 0 {
		if len(args) < 1 {
			_, _ = r.Println("Error: -single-port/-s requires a domain argument")
			os.Exit(1)
		}
		if *singlePort < 1 || *singlePort > 65535 {
			r.Printf("Invalid Port: %d\n", *singlePort)
			os.Exit(1)
		}
		domain := dns_checks.CleanDomain(args[0])
		if !dns_checks.DomainResolves(domain) {
			_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
			os.Exit(1)
		}
		ip := dns_checks.DomainIP(domain)
		y.Println("__________________")
		t.Printf("Checking Port %d\n", *singlePort)
		dns_checks.SinglePortCheck(ip[0], *singlePort)
		os.Exit(0)
	}

	// Handle SSL check
	if *sslCheck {
		if len(args) < 1 {
			_, _ = r.Println("Error: -ssl requires a domain argument")
			os.Exit(1)
		}
		domain := dns_checks.CleanDomain(args[0])
		fmt.Println()
		err := dns_checks.VerifySSL(domain)
		if err != nil {
			_, _ = e.Println(err)
		}
		os.Exit(0)
	}

	// Handle RDAP check
	if *rdapCheck {
		if len(args) < 1 {
			_, _ = r.Println("Error: -rdap/-r requires a domain argument")
			os.Exit(1)
		}
		domain := dns_checks.CleanDomain(args[0])
		y.Println("__________________")
		t.Println("Fetching RDAP/Whois Data")
		err := dns_checks.RdapInfo(domain)
		if err != nil {
			_, _ = e.Println(err)
		}
		os.Exit(0)
	}

	// Handle license check
	if *licenseCheck {
		if len(args) < 1 {
			_, _ = r.Println("Error: -license-check/-l requires an IP address argument")
			os.Exit(1)
		}
		ip := args[0]
		dns_checks.CheckLicense(ip)
		os.Exit(0)
	}
	// Handle PTR record check
	if *ptrrecordCheck {
		if len(args) < 1 {
			_, _ = r.Println("Error PTR Record check failed. Please use -x <IP>.")
			os.Exit(1)
		}
		ip := args[0]
		ptr := dns_checks.ReverseLookup(ip)
		t.Printf("PTR Check: \n \\__ ")
		_, _ = d.Println(ptr)
		os.Exit(0)
	}

	// Handle A record check.
	if *arecordCheck {
		if len(os.Args) < 1 {
			_, _ = r.Println("Error: A record Check failed. Please use -a <domain>")
			os.Exit(1)
		}
		domain := args[0]
		ip := dns_checks.DomainIP(domain)
		if cap(ip) == 1 {
			t.Printf("A record Check: \n \\__ ")
			_, _ = d.Println(strings.Join(ip, ""))
			os.Exit(0)
		} else {
			t.Printf("A record Check:\n")
			y.Println(strings.Repeat("_", len("A record Check")))
			_, _ = d.Println(strings.Join(ip, "\n"))
			os.Exit(0)
		}

	}

	// Default behavior: full domain analysis
	if len(args) < 1 {
		_, _ = r.Println("Error: Domain argument required")
		dns_checks.HelpFunc()
		os.Exit(1)
	}

	domain := dns_checks.CleanDomain(args[0])

	// Pre-check: verify domain resolves before continuing
	if !dns_checks.DomainResolves(domain) {
		_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
		_, _ = t.Println("Attempting to fetch RDAP/Whois data anyway...")

		_ = dns_checks.RdapInfo(domain)
		os.Exit(1)
	}

	fmt.Println()
	seParator := "\t\t\t\t************* DNS INFO *************"
	_, _ = e.Println(seParator)
	fmt.Println()
	if cap(dns_checks.DomainIP(domain)) == 1 {
		_, _ = d.Println("IP: ", strings.Join(dns_checks.DomainIP(domain), ""))
		// _, _ = y.Println("__________________")
	} else {
		_, _ = t.Println("Domain has multiple IP's: ")
		y.Println(strings.Repeat("_", len("Domain has multiple IP's:")))
		for _, ipAddr := range dns_checks.DomainIP(domain) {
			d.Printf("%s\n", ipAddr)
		}
		_, _ = y.Println()
	}

	// IP Info data
	_, _ = t.Println("IP Info Data:")
	y.Println(strings.Repeat("_", len("IP Info Data:")))
	dns_checks.IpInfo(dns_checks.DomainIP(domain)[0])
	fmt.Println()
	// NS Records
	_, _ = t.Println("NS Records:")
	y.Println(strings.Repeat("-", len("NS Records:")))

	_, _ = d.Printf("%s\n", strings.Join(dns_checks.NsLookup(domain), "\n"))
	_, _ = y.Println()
	y.Println(strings.Repeat("-", len("MX Records:")))

	// MX Records
	_, _ = t.Println("MX Records:")
	y.Println(strings.Repeat("-", len("MX Records:")))

	for i, mx := range dns_checks.MxLookup(domain) {
		_, _ = d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	//PTR Records
	_, _ = y.Println("__________________")
	_, _ = d.Println("PTR: ", dns_checks.ReverseLookup(dns_checks.DomainIP(domain)[0]))

	// TXT Records
	_, _ = y.Println("__________________")
	_, _ = t.Println("TXT Records:")
	fmt.Println()
	for _, txt := range dns_checks.TxtCheck(domain) {
		_, _ = d.Printf("Record --> %s\n", txt)

	}

	// SSL Check
	y.Println(strings.Repeat("_", len("SSL Certificate Information:")))
	err := dns_checks.VerifySSL(domain)

	if err != nil {
		_, _ = e.Println(err)
	}
	// Rdap/Whois info
	_, _ = y.Println("__________________")
	_, _ = t.Println("Domain Rdap Data:")
	if err := dns_checks.RdapInfo(domain); err != nil {
		_, _ = e.Println(err)
	}

	// Cloudfalre Check and obtain real IP
	_, _ = y.Println("__________________")
	_, realIP := cloudflareCheckOpt(domain)
	if realIP == "" {
		if !strings.Contains(domain, "mail.") {
			realIP = dns_checks.DomainIP(domain)[0]
			checkOpenPortsWrapperOpt(realIP)
		} else {
			_, _ = d.Println("Mail subdomain does not exist, skipping open ports check")
		}
	} else {
		checkOpenPortsWrapperOpt(realIP)
	}
	// Script elapsed time
	elapsedTime := time.Since(startTime)
	_, _ = t.Printf("Script elapsed time is: %v\n", elapsedTime)
}

// ############### Cloudflare Check Function ##################
func cloudflareCheckOpt(domain string) (bool, string) {
	var prefixedDomain string
	var prefixedDomainIP string
	var baseDomain string

	if strings.Contains(domain, "mail.") {
		prefixedDomainIP = dns_checks.DomainIP(domain)[0]
		prefixedDomain = domain
		baseDomain = strings.TrimPrefix(domain, "mail.")
	} else {
		baseDomain = domain
		prefixedDomain = "mail" + "." + domain
		prefixedDomainIP = dns_checks.DomainIP(prefixedDomain)[0]
	}
	realIP := prefixedDomainIP
	if len(dns_checks.NsLookup(baseDomain)) < 1 {
		_, _ = e.Println("Domain has no NS records")
	} else if strings.Contains(dns_checks.NsLookup(baseDomain)[0], "cloudflare.com") {
		_, _ = t.Println("Domain is using Cloudfalre")
		_, _ = t.Println("Trying to obtain real IP from mail cName")

		results := dns_checks.NsLookup(domain)

		if strings.Contains(results[0], "Cloudflare") {
			_, _ = e.Println("Unable to obtain real IP")
			_, _ = e.Println("Mail cname is also pointed to Cloudfalre")
		} else {
			_, _ = t.Println("Real IP Is: ")
			_, _ = y.Println("__________________")

			_, _ = d.Println("IP: ", realIP)
			_, _ = y.Println()
			// cPanel/WHM License check
			_, _ = y.Println("__________________")
			_, _ = t.Println("cPanel License check")
			dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain)[0])
		}
		return true, realIP
	} else {
		_, _ = t.Println("Domain is not using Cloudflare")
		// cPanel/WHM License check
		_, _ = y.Println("__________________")
		_, _ = t.Println("cPanel License check")
		dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain)[0])
		return false, realIP
	}
	return false, ""
}

func checkOpenPortsWrapperOpt(domain string) {
	// Open Ports Check
	_, _ = y.Println("__________________")
	var choice string
	_, _ = t.Println("Final Stage of the script is Checking for open ports")
	_, _ = t.Println("Please confirm yes or no? - [Y/N]")
	_, _ = fmt.Scanf("%s", &choice)

	switch choice {
	case "y":
		fmt.Println("__________________")
		_, _ = t.Println("Checking Server Default ports")

		dns_checks.PortChecker(domain)

	case "n":
		_, _ = d.Println("Terminating script")
		_, _ = d.Println("See you next time!")
	default:
		_, _ = d.Println("Nothing was selected or input was invalid")
		_, _ = d.Println("Terminating script")
		_, _ = d.Println("See you next time!")

	}

}
