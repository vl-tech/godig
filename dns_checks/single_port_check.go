package dns_checks

import (
	"net"
)

// var (
// 	g = color.New(color.FgHiGreen, color.Bold)
// 	t = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
// 	r = color.New(color.FgHiRed, color.Bold)
// )

func SinglePortCheck(ip string, port string) {
	address := ip + ":" + port
	_, err := net.DialTimeout("tcp", address, 5e9)
	if err != nil {
		r.Printf("  \\___ Port %s is closed\n", port)
	} else {
		g.Printf("  \\___ Port %s is open\n", port)
	}
}
