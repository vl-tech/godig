package main

import (
	"domain_analyzer/dns_checks"
	"fmt"
	"github.com/fatih/color"
	"os"
	"strings"
	"time"
)

var (
	domain    string
	d         = color.New(color.FgHiYellow, color.Bold)
	e         = color.New(color.BgHiMagenta, color.FgYellow, color.Bold)
	t         = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	y         = color.New(color.FgYellow, color.Bold)
	startTime = time.Now()
)

func main() {
	if len(os.Args) < 2 {
		dns_checks.HelpFunc("")
		os.Exit(0)
	} else if len(os.Args) == 2 && os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "--h" {
		dns_checks.HelpFunc(os.Args[1])
		os.Exit(0)
	} else if os.Args[1] == "-nmap" || os.Args[1] == "-n" {
		domain = dns_checks.CleanDomain(os.Args[2])
		ip := dns_checks.DomainIP(domain)
		fmt.Println("__________________")
		t.Println("Checking Server Default ports")
		portStatus := dns_checks.CheckOpenPorts(dns_checks.DomainIP(ip))
		for port, status := range portStatus {
			y.Printf("%d\t%s\n", port, status)
		}
		os.Exit(0)
	} else {
		domain = dns_checks.CleanDomain(os.Args[1])
	}

	fmt.Println()
	seParator := "\t\t\t\t************* DNS INFO *************"
	e.Println(seParator)
	fmt.Println()
	d.Println("IP: ", dns_checks.DomainIP(domain))
	y.Println("__________________")

	// CMS Detection
	t.Println("CMS Detection:")
	cms := dns_checks.DetectCMS(domain)
	d.Println("Detected CMS:", cms)
	y.Println("__________________")

	// IP Info data
	t.Println("IP Info Data: ")
	fmt.Println()
	d.Printf("%s\n", dns_checks.IpInfo(dns_checks.DomainIP(domain)))
	y.Println("__________________")

	// NS Records
	t.Println("NS Records")
	fmt.Println()
	y.Printf("%s\n", strings.Join(dns_checks.NsLookup(domain), "\n"))
	y.Println("__________________")

	// MX Records
	t.Println("MX Records")
	fmt.Println()
	for i, mx := range dns_checks.MxLookup(domain) {
		d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	//PTR Records
	y.Println("__________________")
	d.Println("PTR: ", dns_checks.ReverseLookup(dns_checks.DomainIP(domain)))

	// TXT Records
	y.Println("__________________")
	t.Println("TXT Records")
	fmt.Println()
	for _, txt := range dns_checks.TxtCheck(domain) {

		y.Printf("Record --> %s\n", txt)

	}

	// SSL Check
	y.Println("__________________")
	t.Println("SSL Check")
	err := dns_checks.VerifySSL(domain)
	if err != nil {
		e.Println(err)
	}
	// Rdap/Whois info
	y.Println("__________________")
	t.Println("Domain Rdap Data")
	dns_checks.RdapInfo(domain)

	y.Println("__________________")

	// Cloudfalre Check and obtain real IP
	y.Println("__________________")
	cloudflareCheck(domain)
	checkOpenPortsWrapper(domain)

	// Script elapsed time
	elapsedTime := time.Since(startTime)
	t.Printf("Script elapsed time is: %v\n", elapsedTime)
}

func cloudflareCheck(domain string) {
	var prefixedDomain string
	var prefixedDomainIP string
	if strings.Contains(domain, "mail.") {
		prefixedDomainIP = dns_checks.DomainIP(domain)
	} else {
		prefixedDomain = "mail" + "." + domain
		prefixedDomainIP = dns_checks.DomainIP(prefixedDomain)
	}
	if len(dns_checks.NsLookup(domain)) < 1 {
		e.Println("Domain has no NS records")
	} else if strings.Contains(dns_checks.NsLookup(domain)[0], "cloudflare.com") {
		t.Println("Domain is using Cloudfalre")
		t.Println("Trying to obtain real IP from mail cName")

		resuls := dns_checks.IpInfo(prefixedDomainIP)
		if strings.Contains(resuls, "Cloudflare") {
			e.Println("Unable to obtain real IP")
			e.Println("Mail cname is also pointed to Cloudfalre")
		} else {
			t.Println("Real IP Is: ")
			y.Println("__________________")
			y.Println(dns_checks.DomainIP(prefixedDomain))
			// cPanel/WHM License check
			y.Println("__________________")
			t.Println("cPanel License check")
			dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain))
		}

	} else {
		t.Println("Domain is not using Cloudflare")
		// cPanel/WHM License check
		y.Println("__________________")
		t.Println("cPanel License check")
		dns_checks.CheckLicense(dns_checks.DomainIP(prefixedDomain))

	}

}

func checkOpenPortsWrapper(domain string) {
	// Open Ports Check
	y.Println("__________________")
	var choice string
	t.Println("Final Stage of the script is Checking for open ports")
	t.Println("Please confirm yes or no? - [Y/N]")
	fmt.Scanf("%s", &choice)

	switch choice {
	case "y":
		fmt.Println("__________________")
		t.Println("Checking Server Default ports")
		portStatus := dns_checks.CheckOpenPorts(dns_checks.DomainIP(domain))
		for port, status := range portStatus {
			y.Printf("%d\t%s\n", port, status)
		}

	case "n":
		d.Println("Terminating script")
		d.Println("Bye Bye")
	default:
		d.Println("Nothing was selected or input was invalid")
		d.Println("Terminating script")
		d.Println("Bye Bye")

	}

}
