package dns_checks

import (
	"fmt"
	"net"
)

type MxStats struct {
	Host string
	Prio uint16
}

func MxLookup(domain string) []MxStats {
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
