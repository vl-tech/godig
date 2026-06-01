package dns_checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
)

// VerifySSL connects to port 443 and prints certificate details including issuer, validity dates and days remaining
func VerifySSL(domain string) error {
	y := color.New(color.FgHiGreen, color.Bold)
	m := color.New(color.FgHiMagenta, color.Bold)
	sslDomain := domain + ":443"

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	tlsConfig := &tls.Config{
		ServerName: domain,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", sslDomain, tlsConfig)
	if err != nil {
		return fmt.Errorf("SSL connection error: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.VerifyHostname(domain); err != nil {
		return fmt.Errorf("hostname verification failed: %w", err)
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates found")
	}

	cert := state.PeerCertificates[0]

	totalValidity := cert.NotAfter.Sub(cert.NotBefore)
	totalDays := int(totalValidity.Hours() / 24)
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	m.Printf("SSL Certificate Information: \n\\__\n")
	m.Printf("   %-18s", "|Provider:")
	y.Printf("%v\n", cert.Issuer)
	m.Printf("   %-18s", "|Issued To:")
	y.Printf("%s\n", cert.Subject.CommonName)
	m.Printf("   %-18s", "|Installed On:")
	y.Printf("%d %s %s %d\n", cert.NotBefore.Day(), cert.NotBefore.Month(), cert.NotBefore.Weekday(), cert.NotBefore.Year())
	m.Printf("   %-18s", "|Expiring On:")
	y.Printf("%d %s %s %d\n", cert.NotAfter.Day(), cert.NotAfter.Month(), cert.NotAfter.Weekday(), cert.NotAfter.Year())
	m.Printf("   %-18s", "|Total Validity:")
	y.Printf("%d days\n", totalDays)
	if daysRemaining < 0 {
		m.Printf("   %-18s", "|Status:")
		y.Printf("|EXPIRED (%d days ago)\n", -daysRemaining)
	} else if daysRemaining < 30 {
		m.Printf("   %-18s", "Days Remaining:")
		y.Printf("%d (|EXPIRING SOON!)\n", daysRemaining)
	} else {
		m.Printf("   %-18s", "|Days Remaining:")
		y.Printf("%d\n", daysRemaining)
	}
	return nil
}
