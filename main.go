package main

import (
	"domain_analyzer/dns_checks"
	"strings"

	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

type Dominfo struct {
	IP     string
	PTR    string
	TXT    []string
	MX     []dns_checks.MxStats
	NS     []string
	SSL    error
	IPinfo string
}

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
var domainData Dominfo

func main() {
	d := color.New(color.FgHiCyan, color.Bold)
	t := color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)

	domain := os.Args[1]
	domainData = Dominfo{
		IP:     dns_checks.DomainIP(domain),
		PTR:    dns_checks.ReverseLookup(dns_checks.DomainIP(domain)),
		TXT:    dns_checks.TxtCheck(domain),
		MX:     dns_checks.MxLookup(domain),
		NS:     dns_checks.NsLookup(domain),
		IPinfo: dns_checks.IpInfo(dns_checks.DomainIP(domain)),
	}

	startTime := time.Now()
	seParator := "************* DNS INFO *************"
	t.Println(seParator)
	d.Println("IP: ", domainData.IP)
	fmt.Println("__________________")
	d.Println("IP Info Data: ")
	t.Printf("%s\n", domainData.IPinfo)
	d.Printf("NS Records:\n%s\n", strings.Join(domainData.NS, "\n"))
	fmt.Println("__________________")
	for i, mx := range domainData.MX {
		d.Printf("%d. Host: %s Priority: %d\n", i+1, mx.Host, mx.Prio)
	}

	fmt.Println("__________________")
	d.Println("PTR: ", domainData.PTR)

	fmt.Println("__________________")
	for _, txt := range domainData.TXT {
		d.Println("TXT:", txt)
	}
	fmt.Println("__________________")
	t.Println("SSL Check")
	err := dns_checks.VerifySSL(domain)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("__________________")
	d.Println("Checking Server Defautl ports")
	portStatus := dns_checks.CheckOpenPorts(dns_checks.DomainIP(domain))
	for port, status := range portStatus {
		t.Printf("%d\t%s\n", port, status)
	}
	elapsedTime := time.Since(startTime)
	t.Printf("Script elapsed time is: %v\n", elapsedTime)

}
