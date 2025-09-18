package dns_checks

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
	"github.com/fatih/color"
)

func IpInfo(ip string) string {
	ipinfoBase := "https://ipinfo.io/"
	url := ipinfoBase + ip
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return string(body)
}
func DomainIP(domain string) string {
	e := color.New(color.FgRed, color.Bold)
	ips, err := net.LookupIP(domain)

	if err != nil {
		e.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}

func ReverseLookup(ipAddress string) string {

	ip_data, _ := net.LookupAddr(ipAddress)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error:  %s\n", err)

	// }

	for _, ip := range ip_data {
		return ip
	}

	if len(ip_data) < 1 {
		return "No PTR Found"
	} else {
		return fmt.Sprintf("IP Data%s\n", ip_data)
	}

}

func CnameCheck(domain string) [][]string {
	domPrefix := []string{"www", "cpanel", "whm", "mail"}
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

func TxtCheck(domain string) []string {
	txtData, _ := net.LookupTXT(domain)
	// if err != nil {
	// 	fmt.Printf("TXT Record not found %v\n", err)
	// }
	return txtData
}

func NsLookup(domain string) []string {

	listNS := []string{}
	nsData, err := net.LookupNS(domain)
	if err != nil {
		fmt.Printf("NS Error %s\n", err)
	}
	for _, nsRecord := range nsData {
		listNS = append(listNS, nsRecord.Host)
	}
	return listNS
}

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
func VerifySSL(domain string) error {
	y := color.New(color.FgYellow, color.Bold)
	sslDomain := domain + ":443"

	// Create a dialer with a timeout
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName: domain, // required for proper hostname verification
	}

	// Dial with timeout
	conn, err := tls.DialWithDialer(dialer, "tcp", sslDomain, tlsConfig)
	if err != nil {
		return fmt.Errorf("SSL connection error: %w", err)
	}
	defer conn.Close()

	// Verify hostname (should already be done if ServerName is set in tls.Config)
	if err := conn.VerifyHostname(domain); err != nil {
		return fmt.Errorf("hostname verification failed: %w", err)
	}

	// Grab certificate info
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates found")
	}

	cert := state.PeerCertificates[0]
	y.Printf("Issuer: %s\nExpiry: %v\n", cert.Issuer, cert.NotAfter.Format(time.RFC850))

	return nil
}

func CheckOpenPorts(ip string) map[int]string {

	portStatuses := make(map[int]string)
	timeout := 2 * time.Second
	port_list := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80}
	for _, port := range port_list {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "Port\t%d is closed:\n", port)
			portStatuses[port] = "Closed/Filtered"
			continue
		}
		// t.Printf("Port\t%d is open\n", port)
		portStatuses[port] = "Open"
		conn.Close() // Close only when connection is successful

	}
	return portStatuses
}

func GetRealIp(cNameDomain string) string {
	ips, err := net.LookupIP(cNameDomain)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}
