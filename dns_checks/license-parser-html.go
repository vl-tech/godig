package dns_checks

import (
	"fmt"
	"github.com/fatih/color"
	"io"
	"net/http"
	"regexp"
	"strings"
)

func CheckLicense(ip string) {
	y := color.New(color.FgYellow, color.Bold)
	licensUrl := "https://verify.cpanel.net/app/verify?ip=" + ip
	response, _ := http.Get(licensUrl)
	html_body, _ := io.ReadAll(response.Body)
	// r := regexp.MustCompile(`<td\s+?align?\S+>`)
	r := regexp.MustCompile(`<td align=\"[^>]*>(.*?)<\/td>`)

	if r.MatchString(string(html_body)) == false {
		fmt.Println("License No found")

	} // boolean match only no parsing

	matchList := r.FindAllStringSubmatch(string(html_body), -1)

	matchedStrings := []string{}
	// re := regexp.MustCompile(`<td[^>]*>(.*?)</td>`)
	for _, element := range matchList {

		matchedStrings = append(matchedStrings, strings.ReplaceAll(element[1], "<br/>", ""))
	}
	for _, element := range matchedStrings {
		y.Println(element)
	}

}
