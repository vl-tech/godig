package dns_checks

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

var (
	portsChan   = make(chan int, 100)
	resultsChan = make(chan int)
	g           = color.New(color.FgHiGreen, color.Bold)
	t           = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	r           = color.New(color.FgHiRed, color.Bold)
)

func PortChecker(ip string, port_list []int) {
	// port_list = []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80, 2078, 2079, 2086, 465, 8443, 8080, 5432}
	var openPorts []int
	var closedPorts []int

	for i := 0; i < cap(portsChan); i++ {
		go PortWorker(portsChan, resultsChan, ip)
	}

	go func() {
		for i := range port_list {
			portsChan <- port_list[i]
		}
	}()

	for range port_list {
		port := <-resultsChan
		if port > 0 {
			openPorts = append(openPorts, port)
		} else {
			// Negative port means closed, convert back to positive
			closedPorts = append(closedPorts, -port)
		}

	}

	close(portsChan)
	close(resultsChan)

	sort.Ints(openPorts)
	sort.Ints(closedPorts)
	t.Printf("%-15s %-15s\n", "Open Ports:", "Closed Ports:")
	maxLen := openPorts
	if len(closedPorts) > len(openPorts) {
		maxLen = closedPorts
	}
	for i := 0; i < len(maxLen); i++ {
		var openPortStr, closedPortStr string
		if i < len(openPorts) {
			openPortStr = g.Sprintf("%-15d", openPorts[i])
		} else {
			openPortStr = ""
		}
		if i < len(closedPorts) {
			closedPortStr = r.Sprintf("%-15d", closedPorts[i])
		} else {
			closedPortStr = ""
		}
		fmt.Printf("%-15s %-15s\n", openPortStr, closedPortStr)
	}
}

func PortWorker(ports, results chan int, ip string) {

	for port := range ports {

		address := ip + ":" + fmt.Sprintf("%d", port)
		conn, err := net.DialTimeout("tcp", address, 5e9)

		if err != nil {
			// Send negative port number to indicate closed
			results <- -port
			continue
		}

		conn.Close()
		results <- port
	}

}

func PortRange(args string) []int {
	portList := strings.Split(args, ",")
	var plist []int
	for _, port := range portList {
		intPort, err := strconv.Atoi(port)
		if err != nil {
			r.Println(err)
		}
		plist = append(plist, intPort)
	}
	return plist

}
