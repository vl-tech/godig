package dns_checks

import (
	"github.com/fatih/color"
)

func HelpFunc(input string) {
	y := color.New(color.FgYellow, color.Bold)
	t := color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	functionsList := []string{
		"domain ip check",
		"domain mx check",
		"domain txt check",
		"domain ns check",
		"domain cname check",
		"domain ipinfo check",
		"domain ptr check",
		"ssl validity check ",
		"whois data check",
		"domain get real ip if Cloudflare is used",
	}

	y.Println()
	y.Println("Please enter Valid domain name not FQDN")
	t.Println("Example: <domain.com>, <example.com> ")
	y.Println("-h --help or empty input to display this help message.")
	y.Println("==========================================")
	y.Println("Available Functions\t")
	for _, fn := range functionsList {
		y.Println(fn)
	}

}
