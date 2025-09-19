package dns_checks

import (
	"fmt"
	"net/http"
	"io"
)

func IpInfo(ip string) string {
	ipinfoBase := "https://ipinfo.io/"
	url := ipinfoBase + ip
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return string(body)
}
