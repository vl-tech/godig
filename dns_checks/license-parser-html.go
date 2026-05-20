package dns_checks

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// CheckLicense queries verify.cpanel.net and parses the HTML response to display license status for an IP
func CheckLicense(ip string) {
	licenseURL := "https://verify.cpanel.net/app/verify?ip=" + ip

	// --- HTTP GET ---
	resp, err := http.Get(licenseURL)
	if err != nil {
		fmt.Println("Error fetching license URL:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	htmlBody := string(body)

	// --- Regex to capture all <td> inner content ---
	r := regexp.MustCompile(`(?s)<td\b[^>]*>(.*?)</td>`)
	matches := r.FindAllStringSubmatch(htmlBody, -1)

	if len(matches) == 0 {
		fmt.Println("License not found")
		return
	}

	// --- Regex to strip tags ---
	tagCleaner := regexp.MustCompile(`(?s)<[^>]+>`)

	results := []string{}
	for _, m := range matches {
		raw := m[1]
		// remove tags
		clean := tagCleaner.ReplaceAllString(raw, " ")
		// decode HTML entities
		clean = html.UnescapeString(clean)
		// normalize whitespace
		clean = strings.TrimSpace(strings.Join(strings.Fields(clean), " "))

		// stop if we hit the legend section
		if strings.HasPrefix(clean, "*-") {
			break
		}
		results = append(results, clean)
	}

	// --- Output ---
	dre := regexp.MustCompile(`^[1-9]+$`)
	for _, text := range results {
		digitMatches := dre.FindAllStringSubmatch(text, -1)
		if len(digitMatches) > 0 && text != ip {
			fmt.Printf("\033[1;31mLicense Number: %s\033[0m\n", text)
			continue
		}

		g.Printf("%s\n", text)
	}

}
