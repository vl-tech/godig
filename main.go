package main

import (
	"domain_analyzer/dns_checks"
	"fmt"
	"github.com/fatih/color"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	domain    string
	d         = color.New(color.FgHiGreen, color.Bold)
	e         = color.New(color.BgHiMagenta, color.FgYellow, color.Bold)
	t         = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	y         = color.New(color.FgYellow, color.Bold)
	startTime = time.Now()
	r         = color.New(color.FgRed, color.Bold)
	argSlice  = []string{"--help", "-h", "--h", "-nmap", "-n", "-sp", "--single-port", "-ssl", "-rdap", domain}
)

func main() {

	if len(os.Args) < 2 {
		dns_checks.HelpFunc()
		os.Exit(0)
	} else if len(os.Args) == 2 && os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "--h" {
		dns_checks.HelpFunc()
		os.Exit(0)
	} else if os.Args[1] == "-nmap" || os.Args[1] == "-n" && len(os.Args) > 2 {
		domain = dns_checks.CleanDomain(os.Args[2])
		if !dns_checks.DomainResolves(domain) {
			_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
			os.Exit(1)
		}
		ip := dns_checks.DomainIP(domain)
		y.Println("__________________")
		// CheckPortsWrapper(domain) --- IGNORE ---
		_, _ = t.Println("Checking Server Default ports")
		fmt.Println()
		dns_checks.PortChecker(ip)
		os.Exit(0)

	} else if len(os.Args) > 1 && os.Args[1] == "-sp" || os.Args[1] == "--single-port" {
		requqestedPort := os.Args[3]
		requqestedPortint, err := strconv.Atoi(requqestedPort)
		if err != nil || (requqestedPortint < 1 || requqestedPortint > 65535) {

			r.Printf("Invalid Port: %v\n", requqestedPort)
			os.Exit(1)
		}
		domain = dns_checks.CleanDomain(os.Args[2])
		if !dns_checks.DomainResolves(domain) {
			_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
			os.Exit(1)
		}
		ip := dns_checks.DomainIP(domain)
		y.Println("__________________")
		t.Printf("Checking Port %d\n", requqestedPortint)
		dns_checks.SinglePortCheck(ip, requqestedPortint)
		os.Exit(0)
	} else if len(os.Args) > 1 && os.Args[1] == "-ssl" {
		domain = dns_checks.CleanDomain(os.Args[2])
		y.Println("__________________")
		t.Println("Checking SSL Validity")
		err := dns_checks.VerifySSL(domain)
		if err != nil {
			_, _ = e.Println(err)
		}
		os.Exit(0)
	} else if len(os.Args) > 1 && os.Args[1] == "-rdap" {
		domain = dns_checks.CleanDomain(os.Args[2])
		y.Println("__________________")
		t.Println("Fetching RDAP/Whois Data")
		err := dns_checks.RdapInfo(domain)
		if err != nil {
			_, _ = e.Println(err)
		}
		os.Exit(0)

	} else if !slices.Contains(argSlice, os.Args[1]) && os.Args[1][0] == '-' {
		t.Println("=======> Unknown argument detected <=======")
		dns_checks.HelpFunc()
		os.Exit(0)

	} else if slices.Contains(argSlice, os.Args[1]) && len(os.Args) < 3{
		t.Println("=======> Missing domain argument <=======")
		dns_checks.HelpFunc()
		os.Exit(0)
	} else {
		domain = dns_checks.CleanDomain(os.Args[1])
	}
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
	_, _ = d.Println("IP: ", dns_checks.DomainIP(domain))
	_, _ = y.Println("__________________")

	// CMS Detection
	// _, _ = t.Println("CMS Detection:")
	// cms := dns_checks.DetectCMS(domain)
	// _, _ = d.Println("Detected CMS:", cms)
	// _, _ = y.Println("__________________")

	// IP Info data
	_, _ = t.Println("IP Info Data: ")
	fmt.Println()
	ipInfoData := dns_checks.IpInfo(dns_checks.DomainIP(domain))
	t.Printf("IP: ")
	d.Printf("%s\n", ipInfoData.IP)
	t.Printf("Hostname: ")
	d.Printf("%s\n", ipInfoData.Hostname)
	t.Printf("City: ")
	d.Printf("%s\n", ipInfoData.City)
	t.Printf("Region: ")
	d.Printf("%s\n", ipInfoData.Region)
	t.Printf("Country: ")
	d.Printf("%s\n", ipInfoData.Country)
	t.Printf("Location: ")
	d.Printf("%s\n", ipInfoData.Loc)
	t.Printf("Organization: ")
	d.Printf("%s\n", ipInfoData.Org)
	t.Printf("Postal: ")
	d.Printf("%s\n", ipInfoData.Postal)
	t.Printf("Timezone: ")
	d.Printf("%s\n", ipInfoData.Timezone)
	_, _ = y.Println("__________________")

	// NS Records
	_, _ = t.Println("NS Records:")
	fmt.Println()
	_, _ = d.Printf("%s\n", strings.Join(dns_checks.NsLookup(domain), "\n"))
	_, _ = y.Println("__________________")

	// MX Records
	_, _ = t.Println("MX Records:")
	fmt.Println()
	for i, mx := range dns_checks.MxLookup(domain) {
		_, _ = d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	//PTR Records
	_, _ = y.Println("__________________")
	_, _ = d.Println("PTR: ", dns_checks.ReverseLookup(dns_checks.DomainIP(domain)))

	// TXT Records
	_, _ = y.Println("__________________")
	_, _ = t.Println("TXT Records:")
	fmt.Println()
	for _, txt := range dns_checks.TxtCheck(domain) {
		_, _ = d.Printf("Record --> %s\n", txt)

	}

	// SSL Check
	_, _ = y.Println("__________________")
	_, _ = t.Println("SSL Check:")
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

	_, _ = y.Println("__________________")

	// Cloudfalre Check and obtain real IP
	_, _ = y.Println("__________________")
	// cloudflareCheck(domain)
	// Open Ports Check
	_, _ = y.Println("__________________")
	_, realIP := cloudflareCheck(domain)
	if realIP == "" {
		if !strings.Contains(domain, "mail.") {
			realIP = dns_checks.DomainIP(domain)
			checkOpenPortsWrapper(realIP)
		} else {
			_, _ = d.Println("Mail subdomain does not exist, skipping open ports check")
		}
	} else {
		checkOpenPortsWrapper(realIP)
	}
	// Script elapsed time
	elapsedTime := time.Since(startTime)
	_, _ = t.Printf("Script elapsed time is: %v\n", elapsedTime)
}

func cloudflareCheck(domain string) (bool, string) {
	var prefixedDomain string
	var prefixedDomainIP string
	var baseDomain string

	if strings.Contains(domain, "mail.") {
		prefixedDomainIP = dns_checks.DomainIP(domain)
		prefixedDomain = domain
		baseDomain = strings.TrimPrefix(domain, "mail.")
	} else {
		baseDomain = domain
		prefixedDomain = "mail" + "." + domain
		prefixedDomainIP = dns_checks.DomainIP(prefixedDomain)
	}
	realIP := prefixedDomainIP
	if len(dns_checks.NsLookup(baseDomain)) < 1 {
		_, _ = e.Println("Domain has no NS records")
	} else if strings.Contains(dns_checks.NsLookup(baseDomain)[0], "cloudflare.com") {
		_, _ = t.Println("Domain is using Cloudfalre")
		_, _ = t.Println("Trying to obtain real IP from mail cName")

		resuls := dns_checks.IpInfo(prefixedDomainIP)

		if strings.Contains(resuls.Org, "Cloudflare") {
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
			dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain))
		}
		return true, realIP
	} else {
		_, _ = t.Println("Domain is not using Cloudflare")
		// cPanel/WHM License check
		_, _ = y.Println("__________________")
		_, _ = t.Println("cPanel License check")
		dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain))
		return false, realIP
	}
	return false, ""
}

func checkOpenPortsWrapper(domain string) {
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
