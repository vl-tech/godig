package dns_checks

import (
	"net"
)

func CnameCheck(domain string) [][]string {
	domPrefix := []string{"mail", "cpanel", "whm", "www", "webmail"}
	cnameList := []string{}
	errorList := []string{}
	mainLis := [][]string{}
	for _, prefix := range domPrefix {
		fullDomain := prefix + "." + domain
		cName, err := net.LookupCNAME(fullDomain)
		if err != nil {
			// fmt.Printf("Domain Error %s\n", err)
			errorList = append(errorList, err.Error())
		}
		cnameList = append(cnameList, cName)

	}
	mainLis = append(mainLis, cnameList, errorList)
	return mainLis
}
