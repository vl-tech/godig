## Golang Domain DNS analyzer.
 *Multi platform script for DNS checks.*
 *Checks A,NS,MX,TXT, and SSL validity* 
 *Accepts single parameter the domain name*
## It has complied executables for Linux/MacOS and Windows.
- dig.exe Is the Windows execution script version
- domain_analyzer is the Linux/MacOS binary

## Examples
Limux/MacOS
```bash
./domain_analyzer google.com
```
Windows
```bash
dig.exe google.com
```

## Build binaries locally 
- git clone repo_url
- cd golang-domain-analyzer
Linux binary Size optimized
```bash
go build -ldflags '-w -s'
```
Windows Binary size optimized
```bash
GOOS=windows GOARCH=amd64 go build -ldflags '-w -s'
```
```bash
mv domain_analyzer.exe dig.exe
```

## Example Usage.
- Single port check
```bash
./domain_analyzer -s 443 example.com
```

- Default cPanel port check
```bash
./domain_analyzer -n example.com
```
## Usage
```bash
Domain Analyzer - DNS Information & Security Tool

USAGE:
  domain_analyzer <domain>                    Run full domain analysis
  domain_analyzer [OPTIONS] <domain> [ARGS]   Run specific checks

OPTIONS:
  -h, --help              Show help
  -a <domain>             Check A record for domain
  -i, --ip <IP>           Get IP information
  -l, --license-check <IP> Check cPanel license for IP
  -n, --nmap <domain>     Run nmap port scan on domain
  -p, --port=<port> <domain>  Check single port on domain
  -r, --rdap <domain>     Get RDAP/Whois information
  -x, --ptr <IP>          PTR (reverse DNS) record check
  --ssl <domain>          Verify SSL certificate

FEATURES:
  • IP Address Resolution
  • MX Records Lookup
  • TXT Records Lookup
  • NS Records Lookup
  • CNAME Records Lookup
  • IP Info (Geolocation, ISP, etc.)
  • PTR (Reverse DNS) Lookup
  • SSL Certificate Validation
  • RDAP/WHOIS Data Retrieval
  • Cloudflare Detection & Real IP Discovery
  • cPanel License Check
  • Port Scanning

EXAMPLES:
  domain_analyzer example.com             Full analysis of example.com
  domain_analyzer https://example.com     URL is automatically parsed to domain
  domain_analyzer -a example.com          Check A record for example.com
  domain_analyzer -n example.com          Port scan example.com
  domain_analyzer -p 443 example.com      Check port 443 on example.com
  domain_analyzer -x 142.250.187.110      Check PTR record for IP 142.250.187.110
  domain_analyzer -i 142.250.187.110      Check IP info from ipinfo.io (142.250.187.110 google IP)
  domain_analyzer -l 192.168.1.1          Check cPanel/WHM license status on given IP
  domain_analyzer --ssl example.com       Verify SSL certificate of example.com
  domain_analyzer -r example.com          Retrieve RDAP/WHOIS info for example.com

NOTE:
  URLs with http:// or https:// prefixes are automatically stripped.
  You can enter either 'example.com' or 'https://example.com'.
```