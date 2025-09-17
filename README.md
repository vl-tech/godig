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
Linux binary
```bash
go build
```
Windows Binary
```bash
GOOS=windows GOARCH=amd64 go build
```
```bash
mv domain_analyzer.exe dig.exe
```