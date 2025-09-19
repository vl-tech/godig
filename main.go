/*
Function calls and variable assignments
ip_address := dns_checks.DomainIP(domain)
dns_checks.CnameCheck(domain)
reverseData := dns_checks.ReverseLookup(ip_address)
dns_checks.CnameCheck(domain)
nsData := dns_checks.NsLookup(domain)
mxData := dns_checks.MxLookup(domain)
dns_checks.VerifySSL(domain)
*/
package main

import (
	"domain_analyzer/dns_checks"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Dominfo struct {
	IP        string
	PTR       string
	TXT       []string
	MX        []dns_checks.MxStats
	NS        []string
	SSL       error
	IPinfo    string
	cNameList [][]string
}

var domainData Dominfo

func main() {
	d := color.New(color.FgHiYellow, color.Bold)
	t := color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	e := color.New(color.BgHiMagenta, color.FgYellow, color.Bold)
	y := color.New(color.FgYellow, color.Bold)
	domain := os.Args[1]
	domainData = Dominfo{
		IP:        dns_checks.DomainIP(domain),
		PTR:       dns_checks.ReverseLookup(dns_checks.DomainIP(domain)),
		TXT:       dns_checks.TxtCheck(domain),
		MX:        dns_checks.MxLookup(domain),
		NS:        dns_checks.NsLookup(domain),
		IPinfo:    dns_checks.IpInfo(dns_checks.DomainIP(domain)),
		cNameList: dns_checks.CnameCheck(domain),
	}

	startTime := time.Now()
	fmt.Println()
	seParator := "\t\t\t\t************* DNS INFO *************"
	e.Println(seParator)
	fmt.Println()
	d.Println("IP: ", domainData.IP)
	y.Println("__________________")
	// IP Info data
	t.Println("IP Info Data: ")
	fmt.Println()
	d.Printf("%s\n", domainData.IPinfo)
	y.Println("__________________")
	// NS Records
	t.Println("NS Records")
	fmt.Println()
	y.Printf("%s\n", strings.Join(domainData.NS, "\n"))
	y.Println("__________________")
	// MX Records
	t.Println("MX Records")
	fmt.Println()
	for i, mx := range domainData.MX {
		d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	//PTR Records
	y.Println("__________________")
	d.Println("PTR: ", domainData.PTR)

	// TXT Records
	y.Println("__________________")
	t.Println("TXT Records")
	fmt.Println()
	for _, txt := range domainData.TXT {

		y.Printf("Record --> %s\n", txt)

	}

	// SSL Check
	y.Println("__________________")
	t.Println("SSL Check")
	err := dns_checks.VerifySSL(domain)
	if err != nil {
		e.Println(err)
	}
	// CNAME Check
	y.Println("__________________")
	t.Println("Checking list of valid CNAME records")
	for _, cn := range domainData.cNameList[0] {
		y.Println(cn)
	}

	y.Println("__________________")
	t.Println("Checking list of invalid CNAME errors")
	for _, cn := range domainData.cNameList[1] {
		y.Println(cn)
	};;
	y.Println("__________________")

	// Cloudfalre Check and obtain real IP
	y.Println("__________________")

	prefixedDomain := "mail" + "." + domain
	prefixedDomainIP := dns_checks.DomainIP(prefixedDomain)
	if strings.Contains(domainData.NS[0], "cloudflare.com") {
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
		}

	} else {
		t.Println("Domain is not using Cloudflare")
	}

	// Checking for Open Ports
	y.Println("__________________")
	var choice string
	t.Println("Final Stage of the script is Checking for open ports")
	t.Println("Please confirm yes or no - y/n ")
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
		os.Exit(0)
	default:
		d.Println("Nothing was selected or input was invalid")
		d.Println("Terminating script")
		d.Println("Bye Bye")
	}

	elapsedTime := time.Since(startTime)
	t.Printf("Script elapsed time is: %v\n", elapsedTime)

}
