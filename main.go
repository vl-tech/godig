package main

import (
	"github.com/vl-tech/godig/dns_checks"
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

func requireArg(args []string, flag string) {
	if len(args) < 1 {
		_, _ = r.Printf("Error: %s requires an argument\n", flag)
		os.Exit(1)
	}
}

func main() {
	help           := getopt.BoolLong("help", 'h', "Show help")
	nmapMode       := getopt.BoolLong("nmap", 'n', "Run nmap port scan on domain")
	ipInfo         := getopt.BoolLong("ip", 'i', "Get IP information")
	singlePort     := getopt.IntLong("port", 'p', 0, "Check single port on domain")
	sslCheck       := getopt.BoolLong("ssl", 0, "Verify SSL certificate")
	rdapCheck      := getopt.BoolLong("rdap", 'r', "Get RDAP/Whois information")
	licenseCheck   := getopt.BoolLong("license-check", 'l', "Check cPanel license for IP")
	ptrrecordCheck := getopt.BoolLong("ptr", 'x', "PTR record check")
	arecordCheck   := getopt.Bool('a', "Check A record")
	checkPortList  := getopt.BoolLong("ports", 0, "Port list")
	nsCheck        := getopt.BoolLong("ns", 0, "NS record check")
	mxCheck        := getopt.BoolLong("mx", 'm', "MX record check")
	customRes      := getopt.BoolLong("dns", 'd', "Custom Dns Resolver")
	cpanelOS       := getopt.BoolLong("cpanel-os", 'c', "List cPanel supported OS versions")
	eolOnly        := getopt.BoolLong("eol", 0, "Show only EOL OS versions (use with --cpanel-os)")
	txtrecord 	   := getopt.BoolLong("txt",0,"TXT Records check")
	rblCheck       := getopt.BoolLong("rbl", 0, "Check IP against DNS blacklists (RBL)")

	getopt.Parse()

	if *help || len(os.Args) == 1 {
		dns_checks.HelpFunc()
		return
	}

	args := getopt.Args()

	if *eolOnly && !*cpanelOS {
		_, _ = r.Println("Error: --eol requires --cpanel-os / -c")
		os.Exit(1)
	}

	if *checkPortList  { handlePortList(args) }
	if *customRes      { handleCustomDNS(args) }
	if *cpanelOS       { handleCpanelOS(args, *eolOnly) }
	if *nsCheck        { handleNS(args) }
	if *mxCheck        { handleMX(args) }
	if *nmapMode       { handleNmap(args) }
	if *ipInfo         { handleIPInfo(args) }
	if *singlePort > 0 { handleSinglePort(args, *singlePort) }
	if *sslCheck       { handleSSL(args) }
	if *rdapCheck      { handleRDAP(args) }
	if *licenseCheck   { handleLicense(args) }
	if *ptrrecordCheck { handlePTR(args) }
	if *arecordCheck   { handleARecord(args) }
	if *txtrecord      { handleTXTRecord(args) }
	if *rblCheck       { handleRBL(args) }

	handleFullAnalysis(args)
}

func handlePortList(args []string) {
	if len(args) < 2 {
		_, _ = r.Println("Error: --ports requires two arguments: <port-list> <domain/IP>")
		_, _ = r.Println("Example: --ports 80,443,8080 example.com")
		os.Exit(1)
	}
	y.Println("__________________")
	t.Println("Port List Check Mode")
	fmt.Println()
	d.Printf("Target: %s\n", args[1])
	d.Printf("Ports to check: %s\n", args[0])
	y.Println("__________________")
	fmt.Println()
	plist := dns_checks.PortRange(args[0])
	dns_checks.PortChecker(args[1], plist)
	os.Exit(0)
}

func handleTXTRecord(args []string) {
	requireArg(args, "--txt")
	domain := dns_checks.CleanDomain(args[0])
	_, _ = t.Println("TXT Records:")
	y.Println(strings.Repeat("-", len("TXT Records:")))
	records := dns_checks.TxtCheck(domain)
	if len(records) == 0 {
		_, _ = r.Println("No TXT records found")
	} else {
		for i, record := range records {
			_, _ = d.Printf("%d. %s\n", i+1, record)
		}
	}
	_, _ = y.Println()
	os.Exit(0)
}

func handleCustomDNS(args []string) {
	if len(args) < 2 {
		_, _ = r.Println("Error: --dns/-d requires two arguments: <domain> <resolver>")
		_, _ = r.Println("Example: --dns example.com 8.8.8.8")
		os.Exit(1)
	}
	domain := dns_checks.CleanDomain(args[0])
	dns_checks.CustomDnsResolver(domain, args[1])
	os.Exit(0)
}

func handleCpanelOS(args []string, eolOnly bool) {
	filterFamily := ""
	if len(args) > 0 {
		filterFamily = args[0]
	}
	dns_checks.CpanelEolCsvData(filterFamily, eolOnly)
	os.Exit(0)
}

func handleNS(args []string) {
	requireArg(args, "--ns")
	domain := dns_checks.CleanDomain(args[0])
	_, _ = t.Println("NS Records:")
	y.Println(strings.Repeat("-", len("NS Records:")))
	_, _ = d.Printf("%s\n", strings.Join(dns_checks.NsLookup(domain), "\n"))
	_, _ = y.Println()
	os.Exit(0)
}

func handleMX(args []string) {
	requireArg(args, "--mx/-m")
	domain := dns_checks.CleanDomain(args[0])
	_, _ = t.Println("MX Records:")
	y.Println(strings.Repeat("-", len("MX Records:")))
	for i, mx := range dns_checks.MxLookup(domain) {
		_, _ = d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}
	_, _ = y.Println()
	os.Exit(0)
}

func handleNmap(args []string) {
	requireArg(args, "--nmap/-n")
	domain := dns_checks.CleanDomain(args[0])
	if !dns_checks.DomainResolves(domain) {
		_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
		os.Exit(1)
	}
	ip := dns_checks.DomainIP(domain)
	y.Println("__________________")
	_, _ = t.Println("Checking Server Default ports")
	fmt.Println()
	portList := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80, 2078, 2079, 2086, 465, 8443, 8080, 5432}
	dns_checks.PortChecker(ip[0], portList)
	os.Exit(0)
}

func handleIPInfo(args []string) {
	requireArg(args, "--ip/-i")
	dns_checks.IpInfo(args[0])
	os.Exit(0)
}

func handleSinglePort(args []string, port int) {
	requireArg(args, "--port/-p")
	if port < 1 || port > 65535 {
		r.Printf("Invalid Port: %d\n", port)
		os.Exit(1)
	}
	domain := dns_checks.CleanDomain(args[0])
	if !dns_checks.DomainResolves(domain) {
		_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
		os.Exit(1)
	}
	ip := dns_checks.DomainIP(domain)
	y.Println("__________________")
	t.Printf("Checking Port %d\n", port)
	dns_checks.SinglePortCheck(ip[0], port)
	os.Exit(0)
}

func handleSSL(args []string) {
	requireArg(args, "--ssl")
	domain := dns_checks.CleanDomain(args[0])
	fmt.Println()
	if err := dns_checks.VerifySSL(domain); err != nil {
		_, _ = e.Println(err)
	}
	os.Exit(0)
}

func handleRDAP(args []string) {
	requireArg(args, "--rdap/-r")
	domain := dns_checks.CleanDomain(args[0])
	y.Println("__________________")
	t.Println("Fetching RDAP/Whois Data")
	if err := dns_checks.RdapInfo(domain); err != nil {
		_, _ = e.Println(err)
	}
	os.Exit(0)
}

func handleLicense(args []string) {
	requireArg(args, "--license-check/-l")
	dns_checks.CheckLicense(args[0])
	os.Exit(0)
}

func handlePTR(args []string) {
	requireArg(args, "--ptr/-x")
	ptr := dns_checks.ReverseLookup(args[0])
	t.Printf("PTR Check: \n \\__ ")
	_, _ = d.Println(ptr)
	os.Exit(0)
}

func handleARecord(args []string) {
	requireArg(args, "-a")
	domain := dns_checks.CleanDomain(args[0])
	ip := dns_checks.DomainIP(domain)
	if len(ip) == 1 {
		t.Printf("A record Check: \n \\__ ")
		_, _ = d.Println(strings.Join(ip, ""))
	} else {
		t.Printf("A record Check:\n")
		y.Println(strings.Repeat("_", len("A record Check")))
		_, _ = d.Println(strings.Join(ip, "\n"))
	}
	os.Exit(0)
}

func handleRBL(args []string) {
	requireArg(args, "--rbl")
	dns_checks.RblCheck(args[0])
	os.Exit(0)
}

func handleFullAnalysis(args []string) {
	if len(args) < 1 {
		_, _ = r.Println("Error: Domain argument required")
		dns_checks.HelpFunc()
		os.Exit(1)
	}

	domain := dns_checks.CleanDomain(args[0])

	if !dns_checks.DomainResolves(domain) {
		_, _ = r.Printf("Error: Domain '%s' does not resolve. Cannot continue.\n", domain)
		_, _ = t.Println("Attempting to fetch RDAP/Whois data anyway...")
		_ = dns_checks.RdapInfo(domain)
		os.Exit(1)
	}

	ips := dns_checks.DomainIP(domain)

	fmt.Println()
	_, _ = e.Println("\t\t\t\t************* DNS INFO *************")
	fmt.Println()

	if len(ips) == 1 {
		_, _ = d.Println("IP: ", ips[0])
	} else {
		_, _ = t.Println("Domain has multiple IP's: ")
		y.Println(strings.Repeat("_", len("Domain has multiple IP's:")))
		for _, ipAddr := range ips {
			d.Printf("%s\n", ipAddr)
		}
		_, _ = y.Println()
	}

	_, _ = t.Println("IP Info Data:")
	y.Println(strings.Repeat("_", len("IP Info Data:")))
	dns_checks.IpInfo(ips[0])
	fmt.Println()

	_, _ = t.Println("NS Records:")
	y.Println(strings.Repeat("-", len("NS Records:")))
	_, _ = d.Printf("%s\n", strings.Join(dns_checks.NsLookup(domain), "\n"))
	_, _ = y.Println()
	y.Println(strings.Repeat("-", len("MX Records:")))

	_, _ = t.Println("MX Records:")
	y.Println(strings.Repeat("-", len("MX Records:")))
	for i, mx := range dns_checks.MxLookup(domain) {
		_, _ = d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	_, _ = y.Println("__________________")
	_, _ = d.Println("PTR: ", dns_checks.ReverseLookup(ips[0]))

	dns_checks.RblCheck(ips[0])

	_, _ = y.Println("__________________")
	_, _ = t.Println("TXT Records:")
	fmt.Println()
	for _, txt := range dns_checks.TxtCheck(domain) {
		_, _ = d.Printf("Record --> %s\n", txt)
	}

	y.Println(strings.Repeat("_", len("SSL Certificate Information:")))
	if err := dns_checks.VerifySSL(domain); err != nil {
		_, _ = e.Println(err)
	}

	_, _ = y.Println("__________________")
	_, _ = t.Println("Domain Rdap Data:")
	if err := dns_checks.RdapInfo(domain); err != nil {
		_, _ = e.Println(err)
	}

	_, _ = y.Println("__________________")
	realIP := cloudflareCheckOpt(domain)
	if realIP == "" {
		if !strings.Contains(domain, "mail.") {
			checkOpenPortsWrapperOpt(ips[0])
		} else {
			_, _ = d.Println("Mail subdomain does not exist, skipping open ports check")
		}
	} else {
		checkOpenPortsWrapperOpt(realIP)
	}

	elapsedTime := time.Since(startTime)
	_, _ = t.Printf("Script elapsed time is: %v\n", elapsedTime)
}

func cloudflareCheckOpt(domain string) string {
	var prefixedDomain string
	var prefixedDomainIP string
	var baseDomain string

	if strings.Contains(domain, "mail.") {
		domainIPs := dns_checks.DomainIP(domain)
		if len(domainIPs) == 0 {
			_, _ = e.Printf("Unable to resolve domain: %s\n", domain)
			return ""
		}
		prefixedDomainIP = domainIPs[0]
		prefixedDomain = domain
		baseDomain = strings.TrimPrefix(domain, "mail.")
	} else {
		baseDomain = domain
		prefixedDomain = "mail." + domain
		mailIPs := dns_checks.DomainIP(prefixedDomain)
		if len(mailIPs) == 0 {
			_, _ = r.Printf("Unable to resolve mail subdomain: %s\n", prefixedDomain)
			_, _ = r.Println("Skipping Cloudflare check and license verification")
			return ""
		}
		prefixedDomainIP = mailIPs[0]
	}

	realIP := prefixedDomainIP
	nsRecords := dns_checks.NsLookup(baseDomain)
	if len(nsRecords) < 1 {
		_, _ = e.Println("Domain has no NS records")
	} else if strings.Contains(nsRecords[0], "cloudflare.com") {
		_, _ = t.Println("Domain is using Cloudflare")
		_, _ = t.Println("Trying to obtain real IP from mail cName")
		results := dns_checks.NsLookup(domain)
		if len(results) > 0 && strings.Contains(results[0], "Cloudflare") {
			_, _ = e.Println("Unable to obtain real IP")
			_, _ = e.Println("Mail cname is also pointed to Cloudflare")
		} else {
			_, _ = t.Println("Real IP Is: ")
			_, _ = y.Println("__________________")
			_, _ = d.Println("IP: ", realIP)
			_, _ = y.Println()
			_, _ = y.Println("__________________")
			_, _ = t.Println("cPanel License check")
			licenseIPs := dns_checks.DomainIP(prefixedDomain)
			if len(licenseIPs) > 0 {
				dns_checks.CheckLicense(licenseIPs[0])
			}
		}
		return realIP
	} else {
		_, _ = t.Println("Domain is not using Cloudflare")
		_, _ = y.Println("__________________")
		_, _ = t.Println("cPanel License check")
		licenseIPs := dns_checks.DomainIP(prefixedDomain)
		if len(licenseIPs) > 0 {
			dns_checks.CheckLicense(licenseIPs[0])
		}
		return realIP
	}
	return ""
}

func checkOpenPortsWrapperOpt(domain string) {
	_, _ = y.Println("__________________")
	var choice string
	_, _ = t.Println("Final Stage of the script is Checking for open ports")
	_, _ = t.Println("Please confirm yes or no? - [Y/N]")
	_, _ = fmt.Scanf("%s", &choice)

	switch strings.ToLower(choice) {
	case "y":
		fmt.Println("__________________")
		_, _ = t.Println("Checking Server Default ports")
		portList := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80, 2078, 2079, 2086, 465, 8443, 8080, 5432}
		dns_checks.PortChecker(domain, portList)
	case "n":
		_, _ = d.Println("Terminating script")
		_, _ = d.Println("See you next time!")
	default:
		_, _ = d.Println("Nothing was selected or input was invalid")
		_, _ = d.Println("Terminating script")
		_, _ = d.Println("See you next time!")
	}
}
