package dns_checks

import "strings"

// CleanDomain removes protocol and trailing slash from input
func CleanDomain(input string) string {
    input = strings.TrimSpace(input)
    input = strings.TrimPrefix(input, "https://")
    input = strings.TrimPrefix(input, "http://")
    input = strings.TrimSuffix(input, "/")
    return input
}
