package dns_checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func DomainIP(domain string) string {
	ips, err := net.LookupIP(domain)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse data %s\n", err)
	}
	for _, ip := range ips {
		return ip.String()
	}
	return ""
}

func ReverseLookup(ipAddress string) string {

	ip_data, err := net.LookupAddr(ipAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error:  %s\n", err)

	}
	
	for _, ip := range ip_data {
		return ip
	}

	if len(ip_data) <1{
		return "No PTR Found"
	}else{
		return fmt.Sprintf("IP Data\n", ip_data)
	}
	
}

func CnameCheck(domain string) string {
	cName, err := net.LookupCNAME(domain)
	if err != nil {
		fmt.Printf("Domain Error %s\n", err)
		os.Exit(1)
	}

	return cName
}

func TxtCheck(domain string) []string {
	txtData, err := net.LookupTXT(domain)
	if err != nil {
		fmt.Printf("TXT Record not found %v\n", err)
	}
	return txtData
}

func NsLookup(domain string) []*net.NS {
	nsData, err := net.LookupNS(domain)
	if err != nil {
		fmt.Printf("NS Error %s\n", err)
	}
	return nsData
}

func MxLookup(domain string) []*net.MX {
	mxData, err := net.LookupMX(domain)
	if err != nil {
		fmt.Println("MX Error", err)
	}
	return mxData
}

func VerifySSL(domain string) error {
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
	fmt.Printf("Issuer: %s\nExpiry: %v\n", cert.Issuer, cert.NotAfter.Format(time.RFC850))

	return nil
}


