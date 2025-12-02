package dns_checks

import (
	"fmt"

	"github.com/fatih/color"
)

func HelpFunc(input string) {
	title := color.New(color.FgHiCyan, color.Bold)
	cmd := color.New(color.FgHiGreen, color.Bold)
	desc := color.New(color.FgYellow)
	section := color.New(color.FgHiMagenta, color.Bold)

	fmt.Println()
	title.Println("Domain Analyzer - DNS Information & Security Tool")
	fmt.Println()

	section.Println("USAGE:")
	fmt.Println("  domain_analyzer <domain>                    Run full domain analysis")
	fmt.Println("  domain_analyzer [OPTIONS] <domain> [ARGS]   Run specific checks")
	fmt.Println()

	section.Println("OPTIONS:")
	cmd.Print("  -h, --help              ")
	desc.Println("Display this help message")
	cmd.Print("  -n, -nmap <domain>      ")
	desc.Println("Scan common ports on the domain")
	cmd.Print("  -sp, --single-port <domain> <port>  ")
	desc.Println("Check a specific port")
	fmt.Println()

	section.Println("FEATURES:")
	fmt.Println("  • IP Address Resolution")
	fmt.Println("  • MX Records Lookup")
	fmt.Println("  • TXT Records Lookup")
	fmt.Println("  • NS Records Lookup")
	fmt.Println("  • CNAME Records Lookup")
	fmt.Println("  • IP Info (Geolocation, ISP, etc.)")
	fmt.Println("  • PTR (Reverse DNS) Lookup")
	fmt.Println("  • SSL Certificate Validation")
	fmt.Println("  • RDAP/WHOIS Data Retrieval")
	fmt.Println("  • Cloudflare Detection & Real IP Discovery")
	fmt.Println("  • cPanel License Check")
	fmt.Println("  • Port Scanning")
	fmt.Println()

	section.Println("EXAMPLES:")
	cmd.Print("  domain_analyzer example.com              ")
	desc.Println("Full analysis of example.com")
	cmd.Print("  domain_analyzer https://example.com     ")
	desc.Println("URL is automatically parsed to domain")
	cmd.Print("  domain_analyzer -n example.com          ")
	desc.Println("Port scan example.com")
	cmd.Print("  domain_analyzer -sp example.com 443     ")
	desc.Println("Check port 443 on example.com")
	fmt.Println()

	section.Println("NOTE:")
	desc.Println("  URLs with http:// or https:// prefixes are automatically stripped.")
	desc.Println("  You can enter either 'example.com' or 'https://example.com'.")
	fmt.Println()
}
