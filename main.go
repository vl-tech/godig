package main

import (
	"domain_analyzer/dns_checks"
	"fmt"
	"log"
	"os"
	"time"
	"github.com/fatih/color"
)

func main() {

	d := color.New(color.FgHiCyan, color.Bold)
	// b := color.New(color.FgHiWhite, color.Bold)
	s := color.New(color.FgYellow, color.Bold)
	t := color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)

	startTime := time.Now()
	seParator := "==============================="
	domain := os.Args[1]
	ip_address := dns_checks.DomainIP(domain)
	t.Println("The IP address is : ")
	d.Printf("%s\n", ip_address)
	s.Printf("%s\n", seParator)
	t.Println("Reverse IP Lookup/PTR")
	reverseData := dns_checks.ReverseLookup(ip_address)
	if reverseData == os.Stderr.Name() {
		fmt.Fprintf(os.Stderr, "ReverSeLookup Error")
		os.Exit(1)
	}
	d.Printf("%s\n", reverseData)
	s.Printf("%s\n", seParator)

	d.Printf("CNAME: %s\n", dns_checks.CnameCheck(domain))
	s.Printf("%s\n", seParator)
	t.Println("Checking for TXT Records")
	for _, txtData := range dns_checks.TxtCheck(domain) {
		d.Printf("%s\n", txtData)
	}

	s.Printf("%s\n", seParator)
	nsData := dns_checks.NsLookup(domain)
	t.Println("NS records:")
	for _, nsRecord := range nsData {
		d.Printf("%s\n", nsRecord.Host)
	}

	s.Printf("%s\n", seParator)
	t.Println("MX Records:")

	mxData := dns_checks.MxLookup(domain)
	for _, mxRecord := range mxData {
		d.Printf("MX: %s Priority: %d\n", mxRecord.Host, mxRecord.Pref)
	}

	s.Printf("%s\n", seParator)
	elapsedTime := time.Since(startTime)
	t.Println("Script elapsed time is: ", elapsedTime)
	s.Printf("%s\n", seParator)
	t.Println("SSL Check")

	err := dns_checks.VerifySSL(domain)
	if err != nil {
		log.Fatal(err)
	}

}
