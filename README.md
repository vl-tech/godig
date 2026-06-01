<div align="center">
  <img src="media/dig-logo-new.png" width="250">
  
## godig — Go Domain DNS Analyzer
 *Multi-platform CLI tool for DNS checks.*  
 *Checks A, NS, MX, TXT, PTR, SSL, RDAP, RBL and more.*
</div>

## Build

```bash
git clone <repo_url>
cd godig
```

Linux/macOS — size optimized:
```bash
go build -ldflags '-w -s' -o domain_analyzer
```

Windows — size optimized:
```bash
GOOS=windows GOARCH=amd64 go build -ldflags '-w -s' -o dig.exe
```

Use the appropriate `GOARCH` for your target architecture. List all available values with:
```bash
go tool dist list
```

## Quick Examples

Full domain analysis:
```bash
./domain_analyzer example.com
```

Single port check:
```bash
./domain_analyzer -p 443 example.com
```

Default cPanel port scan:
```bash
./domain_analyzer -n example.com
```

## Usage
```
Domain Analyzer - DNS Information & Security Tool

USAGE:
  domain_analyzer <domain>                    Run full domain analysis
  domain_analyzer [OPTIONS] <domain> [ARGS]   Run specific checks

OPTIONS:
 -a                Check A record
 -c, --cpanel-os   List cPanel supported OS versions
     --eol         Show only EOL OS versions (use with --cpanel-os)
 -d, --dns         Custom DNS resolver
 -h, --help        Show help
 -i, --ip          Get IP information
 -l, --license-check
                   Check cPanel license for IP
 -m, --mx          MX record check
 -n, --nmap        Run nmap port scan on domain
     --ns          NS record check
 -p, --port=value  Check single port on domain
     --ports       Port list
 -r, --rdap        Get RDAP/Whois information
     --ssl         Verify SSL certificate
     --txt         TXT records check (SPF, DKIM, DMARC)
 -x, --ptr         PTR record check
     --rbl         Check IP/domain against DNS blacklists (Spamhaus, Barracuda, SpamCop, SORBS)

FEATURES:
  • IP Address Resolution
  • A, NS, MX, TXT Records Lookup (SPF, DKIM, DMARC included in TXT)
  • PTR (Reverse DNS) Lookup
  • IP Info (Geolocation, ISP, etc.)
  • SSL Certificate Validation
  • RDAP/WHOIS Data Retrieval
  • Cloudflare Detection & Real IP Discovery
  • cPanel License Check
  • cPanel Supported OS Versions Lookup (with EOL detection)
  • RBL Blacklist Check (Spamhaus zen, Barracuda, SpamCop, SORBS)
  • Port Scanning (single, list, or full cPanel default ports)
  • Custom DNS Resolver Support

EXAMPLES:
  domain_analyzer example.com                      Full analysis of example.com
  domain_analyzer https://example.com              URL is automatically parsed to domain
  domain_analyzer -a example.com                   Check A record for example.com
  domain_analyzer -m example.com                   Check MX records for example.com
  domain_analyzer -n example.com                   Port scan example.com
  domain_analyzer --ns example.com                 Check NS records for example.com
  domain_analyzer -p 443 example.com               Check port 443 on example.com
  domain_analyzer --ports 80,443,8080 example.com  Check specific ports on example.com
  domain_analyzer -x 142.250.187.110               Check PTR record for IP 142.250.187.110
  domain_analyzer -i 142.250.187.110               Check IP info from ipinfo.io
  domain_analyzer -i myip                          Check your public IP
  domain_analyzer -l 192.168.1.1                   Check cPanel/WHM license status on given IP
  domain_analyzer --ssl example.com                Verify SSL certificate of example.com
  domain_analyzer -r example.com                   Retrieve RDAP/WHOIS info for example.com
  domain_analyzer -d example.com 8.8.8.8           Query example.com using Google DNS (8.8.8.8)
  domain_analyzer --cpanel-os                      List all cPanel supported OS versions
  domain_analyzer --cpanel-os Ubuntu               List cPanel OS versions for Ubuntu family
  domain_analyzer --cpanel-os --eol                List only EOL OS versions
  domain_analyzer -c CentOS --eol                  List EOL CentOS versions
  domain_analyzer --txt example.com                Check all TXT records (SPF, DKIM, DMARC)
  domain_analyzer --rbl example.com                Check if example.com IP is on any blacklist
  domain_analyzer --rbl 1.2.3.4                    Check if IP 1.2.3.4 is on any blacklist

NOTE:
  You can pass either 'example.com' or 'https://example.com' — the URL is parsed automatically.

## License

MIT — see [LICENSE](LICENSE).
