package main

import (
	"domain_analyzer/dns_checks"

	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

type Dominfo struct {
	IP  string
	PTR string
	TXT []string
	MX  []any
	NS  []string
	SSL error
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
		IP:  dns_checks.DomainIP(domain),
		PTR: dns_checks.ReverseLookup(dns_checks.DomainIP(domain)),
		TXT: dns_checks.TxtCheck(domain),
		MX:  dns_checks.MxLookup(domain),
		NS:  dns_checks.NsLookup(domain),
	}

	startTime := time.Now()
	seParator := "************* DNS INFO *************"
	t.Println(seParator)
	d.Println("IP: ", domainData.IP)
	fmt.Println("__________________")
	d.Println("NS: ", domainData.NS)
	fmt.Println("__________________")
	d.Println("MX: ", domainData.MX)
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

	elapsedTime := time.Since(startTime)
	t.Printf("Script elapsed time is: %v\n", elapsedTime)

}
