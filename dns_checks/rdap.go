package dns_checks

import (
	"github.com/fatih/color"
	"github.com/openrdap/rdap"
	"log"
)

func RdapInfo(domain string) {
	y := color.New(color.FgYellow, color.Bold)
	r := color.New(color.FgRed, color.Bold)

	client := &rdap.Client{}
	dataList := []string{}
	domainInfo, err := client.QueryDomain(domain)
	if err != nil {
		log.Fatal("Domain error\t", err)
	}

	dataList = append(dataList, domainInfo.Handle, domainInfo.Lang)
	for _, stat := range domainInfo.Status {
		r.Println("Status: ", stat)
	}
	r.Println("Rdap Url: ", domainInfo.Links[0].Href)
	y.Println("Domain: ", domainInfo.Events[0].Action, domainInfo.Events[0].Date)
	y.Println("Domain: ", domainInfo.Events[1].Action, domainInfo.Events[1].Date)
	y.Println("Domain: ", domainInfo.Events[2].Action, domainInfo.Events[2].Date)
	y.Printf("Registrar: %s [%s %s]\n", domainInfo.Entities[2].VCard.Name(),domainInfo.Entities[2].VCard.Locality(), domainInfo.Entities[2].VCard.Region())
	nsData := domainInfo.Nameservers
	y.Printf("NS1: %s\nNS2: %s\n", nsData[0].LDHName, nsData[1].LDHName)
	// fmt.Println(dataList)

}
