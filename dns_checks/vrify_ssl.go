package dns_checks

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
)

func VerifySSL(domain string) error {
	y := color.New(color.FgHiGreen, color.Bold)
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
	defer func() { _ = conn.Close() }()

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

	// Calculate validity duration and days remaining
	totalValidity := cert.NotAfter.Sub(cert.NotBefore)
	totalDays := int(totalValidity.Hours() / 24)
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	t.Println("SSL Certificate Information:")
	y.Println("Provider", cert.Issuer)
	y.Println("Issued To: ", cert.Subject.CommonName)
	y.Println("Installed On: ", cert.NotBefore.Day(), cert.NotBefore.Month(), cert.NotBefore.Weekday(), cert.NotBefore.Year())
	y.Println("Expiring On: ", cert.NotAfter.Day(), cert.NotAfter.Month(), cert.NotAfter.Weekday(), cert.NotAfter.Year())
	y.Printf("Total Validity: %d days\n", totalDays)
	if daysRemaining < 0 {
		y.Printf("Status: EXPIRED (%d days ago)\n", -daysRemaining)
	} else if daysRemaining < 30 {
		y.Printf("Days Remaining: %d (EXPIRING SOON!)\n", daysRemaining)
	} else {
		y.Printf("Days Remaining: %d\n", daysRemaining)
	}
	return nil
}
