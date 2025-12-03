package dns_checks

import (
	"fmt"
	"net"
)

// var (
// 	g = color.New(color.FgHiGreen, color.Bold)
// 	t = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
// 	r = color.New(color.FgHiRed, color.Bold)
// )

func SinglePortCheck(ip string, port int) {
	address := ip + ":" + fmt.Sprintf("%d", port)
	_, err := net.DialTimeout("tcp", address, 5e9)
	if err != nil {
		r.Printf("  \\___ Port %d is closed\n", port)
	} else {
		g.Printf("  \\___ Port %d is open\n", port)
	}
}
