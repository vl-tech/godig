package dns_checks

import (
	"fmt"
	"net"
	"strings"
)

type MxStats struct {
	Host string
	Prio uint16
}

func MxLookup(domain string) []MxStats {
	if strings.Contains(domain, "mail") {
		domain = strings.Replace(domain, "mail.", "", 1)
		if len(strings.Split(domain, ".")) > 2 {
			domain = strings.Join(strings.Split(domain, ".")[1:], ".")
		}
	}
	mxData, err := net.LookupMX(domain)
	if err != nil {
		fmt.Println("MX Error", err)
	}
	mxList := make([]MxStats, 0, len(mxData))
	for _, mx := range mxData {
		mxList = append(mxList, MxStats{
			Host: mx.Host,
			Prio: mx.Pref,
		})
	}
	return mxList
}
