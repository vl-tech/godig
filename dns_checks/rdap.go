package dns_checks

import (
	"strings"

	"github.com/fatih/color"
	"github.com/openrdap/rdap"
)

func RdapInfo(domain string) error {
	y := color.New(color.FgHiGreen, color.Bold)
	r := color.New(color.FgRed, color.Bold)
	// if strings.Contains(domain, "mail") {
	// 	domain = strings.Replace(domain, "mail.", "", 1)
	// 	if len(strings.Split(domain, ".")) > 2 {
	// 		domain = strings.Join(strings.Split(domain, ".")[1:], ".")
	// 	}
	// }
	if strings.Contains(domain, "mail") || len(strings.Split(domain, ".")) > 2 {
		domain = strings.Join(strings.Split(domain, ".")[1:], ".")
	}
	client := &rdap.Client{}
	// dataList was introduced previously but not used; omit it to avoid ineffassign
	domainInfo, err := client.QueryDomain(domain)
	if err != nil {
		_, _ = r.Println(err)
		_, _ = r.Println("Checking Whois data")
		_, _ = y.Println("__________________")
		// Fall back to WHOIS if RDAP fails
		_ = WhoisDomain(domain)
		return nil
	}
	for _, stat := range domainInfo.Status {
		_, _ = r.Println("Status: ", stat)
	}

	_, _ = r.Println("Rdap Url: ", domainInfo.Links[0].Href)
	for _, event := range domainInfo.Events {
		_, _ = y.Println("Domain : ", event.Action, event.Date)
	}
	if len(domainInfo.Entities) < 3 {

		_, _ = r.Println("Registrar: ", domainInfo.Entities[0].VCard.Name())
	} else {
		_, _ = y.Printf("Registrar: %s [%s %s]\n", domainInfo.Entities[3].VCard.Name(), domainInfo.Entities[3].VCard.Locality(), domainInfo.Entities[3].VCard.Region())
	}
	nsData := domainInfo.Nameservers
	t.Println("NS Data:")
	for i := range nsData {
		_, _ = y.Printf("%s\n", nsData[i].LDHName)
	}

	return nil

}
