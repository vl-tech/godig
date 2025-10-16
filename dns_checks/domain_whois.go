package dns_checks

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func WhoisDomain(domain string) error {
	y := color.New(color.FgYellow, color.Bold)
	whois_raw, err := whois.Whois(domain)
	if err != nil {
		fmt.Println(err)
	}
	info, err := whoisparser.Parse(whois_raw)
	if err != nil {
		fmt.Printf("No Whois data for Domain %s Error: %v\n ", domain, err)
	}

	if info.Domain != nil {
		y.Println("Domain:", info.Domain.Domain)
		y.Println("Created:", info.Domain.CreatedDate)
		y.Println("Expires:", info.Domain.ExpirationDate)
		y.Println("Name Servers:", info.Domain.NameServers)
		y.Println("Status:", info.Domain.Status)
	}
	if info.Registrar != nil {
		y.Println("Registrar Name:", info.Registrar.Name)
	}
	return nil
}
