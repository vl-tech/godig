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
./domain_analyzer -sp ip_addr/domain port
```

- Default cPanel port check
```bash
./domain_analyzer -nmap ip_addr/domain port
```
## Usage
```bash
Domain Analyzer - DNS Information & Security Tool

USAGE:
  domain_analyzer <domain>                    Run full domain analysis
  domain_analyzer [OPTIONS] <domain> [ARGS]   Run specific checks

OPTIONS:
  -h, --help              Display this help message
  -n, -nmap <domain>      Scan common ports on the domain
  -sp, --single-port <domain> <port>  Check a specific port

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
  domain_analyzer example.com              Full analysis of example.com
  domain_analyzer https://example.com     URL is automatically parsed to domain
  domain_analyzer -n example.com          Port scan example.com
  domain_analyzer -sp example.com 443     Check port 443 on example.com

NOTE:
  URLs with http:// or https:// prefixes are automatically stripped.
  You can enter either 'example.com' or 'https://example.com'.
```