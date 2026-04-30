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

func IpInfo(ip string) {
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
	t.Printf("IP: ")
	d.Printf("%s\n", ipInfoData.IP)

	if ipInfoData.Hostname != "" {
		t.Printf("Hostname: ")
		d.Println(ipInfoData.Hostname)
	} else {
		t.Printf("%s:", "Hostname")
		r.Printf("%s\n", "Not Found!")
	}

	t.Printf("City: ")
	d.Printf("%s\n", ipInfoData.City)
	t.Printf("Region: ")
	d.Printf("%s\n", ipInfoData.Region)
	t.Printf("Country: ")
	d.Printf("%s\n", ipInfoData.Country)
	t.Printf("Location: ")
	d.Printf("%s\n", ipInfoData.Loc)
	t.Printf("Organization: ")
	d.Printf("%s\n", ipInfoData.Org)
	t.Printf("Postal: ")
	d.Printf("%s\n", ipInfoData.Postal)
	t.Printf("Timezone: ")
	d.Printf("%s\n", ipInfoData.Timezone)
}
