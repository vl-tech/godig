package dns_checks

import (

	"github.com/fatih/color"
	"github.com/openrdap/rdap"
)

func RdapInfo(domain string) error {
	y := color.New(color.FgYellow, color.Bold)
	r := color.New(color.FgRed, color.Bold)

	client := &rdap.Client{}
	dataList := []string{}
	domainInfo, err := client.QueryDomain(domain)
	if err != nil {
		r.Println("Domain error\t", err)
		return err
	}

	dataList = append(dataList, domainInfo.Handle, domainInfo.Lang)
	for _, stat := range domainInfo.Status {
		r.Println("Status: ", stat)
	}

	r.Println("Rdap Url: ", domainInfo.Links[0].Href)
	for _, event := range domainInfo.Events {
		y.Println("Domain : ", event.Action, event.Date)
	}
	if len(domainInfo.Entities) < 3 {
		r.Println("Registrar: ", domainInfo.Entities[0].VCard.Name())
	} else {
		y.Printf("Registrar: %s [%s %s]\n", domainInfo.Entities[2].VCard.Name(), domainInfo.Entities[2].VCard.Locality(), domainInfo.Entities[2].VCard.Region())
	}
	nsData := domainInfo.Nameservers
	for i, _ := range nsData {
		y.Printf("%s\n", nsData[i].LDHName)
	}

	return nil

}
