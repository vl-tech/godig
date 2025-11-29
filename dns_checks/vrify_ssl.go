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
	_, _ = y.Printf("Issuer: %s\nExpiry: %v\n", cert.Issuer, cert.NotAfter.Format(time.RFC850))

	return nil
}
