<div align="center">
  <img src="media/dig-logo-new.png" width="250">
  
## godig — Go Domain DNS Analyzer

 *Multi-platform CLI tool for DNS checks.*  
 *Checks A, NS, MX, TXT, PTR, SSL, RDAP, RBL and more.*
</div>

## Install

```bash
go install github.com/vl-tech/godig@latest
```

This installs the binary as `godig`. Requires Go 1.21+.

## Build from source

```bash
git clone https://github.com/vl-tech/godig.git
cd godig
```

Linux/macOS:

```bash
go build -ldflags '-w -s' -o godig
```

Windows (native):

```bash
go build -ldflags '-w -s' -o godig.exe
```

Cross-compile for Windows from Linux/macOS:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags '-w -s' -o godig.exe
```

Use the appropriate `GOARCH` for your target architecture. List all available values with:

```bash
go tool dist list
```

## Quick Examples

Full domain analysis:

```bash
./godig example.com
```

Single port check:

```bash
./godig -p 443 example.com
```

Default cPanel port scan:

```bash
./godig -n example.com
```

## Usage

```golang
Godig Universal diglike utility - DNS Information & Security Tool

USAGE:
  godig <domain>                    Run full domain analysis
  godig [OPTIONS] <domain> [ARGS]   Run specific checks

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
  godig example.com                      Full analysis of example.com
  godig https://example.com              URL is automatically parsed to domain
  godig -a example.com                   Check A record for example.com
  godig -m example.com                   Check MX records for example.com
  godig -n example.com                   Port scan example.com
  godig --ns example.com                 Check NS records for example.com
  godig -p 443 example.com               Check port 443 on example.com
  godig --ports 80,443,8080 example.com  Check specific ports on example.com
  godig -x 142.250.187.110               Check PTR record for IP 142.250.187.110
  godig -i 142.250.187.110               Check IP info from ipinfo.io
  godig -i myip                          Check your public IP
  godig -l 192.168.1.1                   Check cPanel/WHM license status on given IP
  godig --ssl example.com                Verify SSL certificate of example.com
  godig -r example.com                   Retrieve RDAP/WHOIS info for example.com
  godig -d example.com 8.8.8.8           Query example.com using Google DNS (8.8.8.8)
  godig --cpanel-os                      List all cPanel supported OS versions
  godig --cpanel-os Ubuntu               List cPanel OS versions for Ubuntu family
  godig --cpanel-os --eol                List only EOL OS versions
  godig -c CentOS --eol                  List EOL CentOS versions
  godig --txt example.com                Check all TXT records (SPF, DKIM, DMARC)
  godig --rbl example.com                Check if example.com IP is on any blacklist
  godig --rbl 1.2.3.4                    Check if IP 1.2.3.4 is on any blacklist

```
[!NOTE] You can pass either 'example.com' or 'https://example.com' — the URL is parsed automatically.

## License

MIT — see [LICENSE](LICENSE).
