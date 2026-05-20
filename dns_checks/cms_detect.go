package dns_checks

import (
	"io"
	"net/http"
	"strings"
)

// DetectCMS fetches the domain's HTML and attempts to identify the CMS from meta tags and known markup patterns
func DetectCMS(domain string) string {
	resp, err := http.Get("http://" + domain)
	if err != nil {
		return "Unable to fetch domain"
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// Check for meta generator tag
	if strings.Contains(html, "meta name=\"generator\"") {
		if strings.Contains(html, "WordPress") {
			return "WordPress"
		}
		if strings.Contains(html, "Joomla") {
			return "Joomla"
		}
		if strings.Contains(html, "Drupal") {
			return "Drupal"
		}
		if strings.Contains(html, "Magento") {
			return "Magento"
		}
	}

	// Check for Flask via headers and HTML
	if strings.Contains(html, "Flask") || strings.Contains(html, "Werkzeug") {
		return "Flask (Python)"
	}
	if server := resp.Header.Get("Server"); strings.Contains(server, "Werkzeug") || strings.Contains(server, "Flask") {
		return "Flask (Python)"
	}

	switch {
	case strings.Contains(html, "wp-content") || strings.Contains(html, "wp-includes"):
		return "WordPress"
	case strings.Contains(html, "Joomla!") || strings.Contains(html, "joomla"):
		return "Joomla"
	case strings.Contains(html, "Magento"):
		return "Magento"
	case strings.Contains(html, "Drupal") || strings.Contains(html, "drupal"):
		return "Drupal"
	case strings.Contains(html, "phpBB") || strings.Contains(html, "phpbb"):
		return "phpBB"
	default:
		return "Unknown CMS"
	}

}
