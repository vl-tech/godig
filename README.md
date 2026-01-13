
![LOGO](media/dig-logo-new.png)
</td></tr></table>
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
Windows Binary arm64/arm64/i386 etc. size optimized
```bash
GOOS=windows GOARCH=amd64 go build -ldflags '-w -s'
```
Use appropriate GOARCH value for your target architecture.
You can list all available GOARCH values [here](https://golang.org/doc/install/source#environment).
Or if you have Go installed, run:

```bash
go tool dist list
```
Rename Windows binary to dig.exe
```bash
mv domain_analyzer.exe dig.exe
```

## Example Usage.
- Single port check
```bash
./domain_analyzer -p 443 example.com
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
 -a                Check A record
 -d, --dns         Custom Dns Resolver
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
 -x, --ptr         PTR record check

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
  domain_analyzer -i 142.250.187.110               Check IP info from ipinfo.io (142.250.187.110 google IP)
  domain_analyzer -i myip                          Check IP your Public IP
  domain_analyzer -l 192.168.1.1                   Check cPanel/WHM license status on given IP
  domain_analyzer --ssl example.com                Verify SSL certificate of example.com
  domain_analyzer -r example.com                   Retrieve RDAP/WHOIS info for example.com
  domain_analyzer -d example.com 8.8.8.8           Query example.com using Google DNS (8.8.8.8)

NOTE:
  You can enter either 'example.com' or 'https://example.com'.
```