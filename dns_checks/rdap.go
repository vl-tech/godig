package dns_checks

import (
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/openrdap/rdap"
)

var (
	formats = []string{
		time.RFC3339,
		time.ANSIC,
		time.UnixDate,
		time.RubyDate,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC3339Nano,
		"20060102",                 // .com.br
		"2006-01-02",               // .lt
		"2006-01-02 15:04:05-07",   // .ua
		"2006-01-02 15:04:05",      // .ch
		"2006-01-02T15:04:05Z",     // .name
		"2006-01-02T15:04:05.0Z",   // .host
		"January  2 2006",          // .is
		"02.01.2006",               // .cz
		"02/01/2006",               // .fr
		"02-January-2006",          // .ie
		"2006.01.02 15:04:05",      // .pl
		"02-Jan-2006",              // .co.uk
		"02-Jan-2006 15:04:05",     // .sg
		"2006-01-02T15:04:05Z",     // .co
		"2006/01/02",               // .ca
		"2006-01-02 (YYYY-MM-DD)",  // .tw
		"(dd/mm/yyyy): 02/01/2006", // .pt
		"02-Jan-2006 15:04:05 UTC", // .id, .co.id
		": 2006. 01. 02.",          // .kr
	}
)

// RdapInfo fetches registration data (status, dates, registrar, nameservers) via RDAP for a domain
func RdapInfo(domain string) error {
	y := color.New(color.FgHiGreen, color.Bold)
	r := color.New(color.FgRed, color.Bold)
	t := color.New(color.FgCyan, color.Bold)

	// Clean domain name
	if strings.Contains(domain, "mail") || len(strings.Split(domain, ".")) > 2 {
		domain = strings.Join(strings.Split(domain, ".")[1:], ".")
	}

	// Create RDAP request using &rdap.Request
	req := &rdap.Request{
		Type:  rdap.DomainRequest,
		Query: domain,
	}

	// Execute the request
	client := &rdap.Client{}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = r.Printf("RDAP lookup failed: %v\n", err)
		return nil
	}

	// Type assert the response object
	domainInfo, ok := resp.Object.(*rdap.Domain)
	if !ok {
		_, _ = r.Println("Error: Invalid response type")
		return nil
	}

	// Display status
	for _, stat := range domainInfo.Status {
		_, _ = r.Println("Status: ", stat)
	}

	// Display RDAP URL
	if len(domainInfo.Links) > 0 {
		_, _ = r.Println("Rdap Url: ", domainInfo.Links[0].Href)
	}

	// Display events
	for _, event := range domainInfo.Events {
		formattedDate := formatDate(event.Date)
		_, _ = y.Printf("Domain : %s %s\n", event.Action, formattedDate)
	}

	// Display registrar info
	for _, entity := range domainInfo.Entities {
		if entity.VCard != nil {
			for _, role := range entity.Roles {
				if role == "registrar" {
					_, _ = y.Printf("Registrar: %s [%s %s]\n",
						entity.VCard.Name(),
						entity.VCard.Locality(),
						entity.VCard.Region())
					break
				}
			}
		}
	}

	// Display nameservers
	nsData := domainInfo.Nameservers
	t.Println("NS Data:")
	for i := range nsData {
		_, _ = y.Printf("%s\n", nsData[i].LDHName)
	}

	return nil
}

// formatDate tries multiple date formats and normalises to YYYY-MM-DD HH:MM:SS
func formatDate(dateStr string) string {
	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
	}
	return dateStr
}
