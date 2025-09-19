package dns_checks

import (
	"github.com/openrdap/rdap"
)

func RdapInfo(domain string) []string {
	client := &rdap.Client{}
	dataList := []string{}

	domainInfo, err := client.QueryDomain(domain)
	if err != nil {
		panic(err)
	}
	dataList = append(dataList, domainInfo.Handle, domainInfo.LDHName)
	return dataList

}
