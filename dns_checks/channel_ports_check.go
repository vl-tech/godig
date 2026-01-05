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
	g = color.New(color.FgHiGreen, color.Bold)
	t = color.New(color.BgBlack, color.FgHiMagenta, color.Italic, color.Bold)
	r = color.New(color.FgHiRed, color.Bold)
)

// PortChecker scans ports concurrently and displays open/closed results
func PortChecker(ip string, port_list []int) {
	const maxWorkerCount = 100
	var openPorts []int
	var closedPorts []int
	portsChan := make(chan int, maxWorkerCount)
	resultsChan := make(chan int)
	// Start worker goroutines to check ports concurrently
	for i := 0; i < cap(portsChan); i++ {
		go PortWorker(portsChan, resultsChan, ip)
	}

	// Send ports to channel for workers to process
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

// PortWorker checks if a port is open by attempting TCP connection
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

// PortRange parses comma-separated port string into integer slice
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
