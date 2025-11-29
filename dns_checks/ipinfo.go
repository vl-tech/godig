package dns_checks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type IpInfoDataStruct struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
	Readme   string `json:"readme"`
}

func IpInfo(ip string) IpInfoDataStruct {
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
	ipInfoData := IpInfoDataStruct{}
	err = json.Unmarshal(body, &ipInfoData)
	if err != nil {
		r.Println(err)
	}
	return ipInfoData
}
