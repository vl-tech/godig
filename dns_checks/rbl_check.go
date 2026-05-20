package dns_checks

import (
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"
)

var rblZones = []string{
	"zen.spamhaus.org",
	"b.barracudacentral.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
}

var rblCheckURLs = map[string]string{
	"zen.spamhaus.org":      "https://check.spamhaus.org/",
	"b.barracudacentral.org": "https://www.barracudacentral.org/lookups",
	"bl.spamcop.net":        "https://www.spamcop.net/bl.shtml?",
	"dnsbl.sorbs.net":       "https://www.sorbs.net/lookup.shtml",
}

var spamhausReturnCodes = map[string]string{
	"127.0.0.2":   "SBL — listed for spam activity",
	"127.0.0.3":   "SBL CSS — spam-sending infrastructure (snowshoe/compromised)",
	"127.0.0.4":   "XBL — exploited or infected machine (CBL)",
	"127.0.0.9":   "SBL DROP — do not route or peer",
	"127.0.0.10":  "PBL — dynamic IP, not authorised for direct mail sending",
	"127.0.0.11":  "PBL — customer policy block",
	"127.255.255.254": "Query refused — public resolver detected (e.g. WARP/1.1.1.1). Use a local recursive resolver.",
	"127.255.255.255": "Query refused — unauthorised query source.",
}

// spamhausQueryErrors are return codes that indicate a resolver policy error, not a real listing.
var spamhausQueryErrors = map[string]bool{
	"127.255.255.254": true,
	"127.255.255.255": true,
}

func decodeReturnCode(zone, code string) string {
	if strings.Contains(zone, "spamhaus") {
		if meaning, ok := spamhausReturnCodes[code]; ok {
			return meaning
		}
	}
	return code
}

func RblCheck(target string) {
	good := color.New(color.FgHiGreen, color.Bold)
	bad  := color.New(color.FgRed, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	link := color.New(color.FgHiCyan)
	head := color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)

	ip := target
	if net.ParseIP(target) == nil {
		ips, err := net.LookupHost(target)
		if err != nil || len(ips) == 0 {
			bad.Printf("Could not resolve '%s' to an IP address\n", target)
			return
		}
		ip = ips[0]
		head.Printf("Resolved %s → %s\n", target, ip)
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		bad.Printf("Invalid IPv4 address: %s\n", ip)
		return
	}

	reversed := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])

	fmt.Println()
	head.Printf("RBL Check for %s\n", ip)
	fmt.Println(strings.Repeat("-", 55))

	type listing struct {
		zone    string
		meaning string
		url     string
	}
	var listings []listing

	for _, zone := range rblZones {
		addrs, err := net.LookupHost(reversed + "." + zone)
		if err == nil && len(addrs) > 0 {
			meaning := decodeReturnCode(zone, addrs[0])
			if strings.Contains(zone, "spamhaus") && spamhausQueryErrors[addrs[0]] {
				warn.Printf("SKIPPED %-30s", zone)
				warn.Printf("  %s\n", meaning)
				continue
			}
			bad.Printf("LISTED  %-30s", zone)
			warn.Printf("  %s\n", meaning)

			url := rblCheckURLs[zone]
			if strings.HasSuffix(url, "?") {
				url += ip
			}
			listings = append(listings, listing{zone, meaning, url})
		} else {
			good.Printf("Clean   %s\n", zone)
		}
	}

	fmt.Println()
	if len(listings) > 0 {
		bad.Println("IP is listed on one or more blacklists!")
		fmt.Println()
		head.Println("Check / Delist:")
		fmt.Println(strings.Repeat("-", 55))
		for _, l := range listings {
			warn.Printf("  %-28s  ", l.zone)
			link.Println(l.url)
		}
		fmt.Println()
	} else {
		good.Println("IP is not listed on any checked blacklists")
	}
}
