package dns_checks

import (
	"fmt"
	"net"
	"time"
)

func CheckOpenPorts(ip string) map[int]string {

	portStatuses := make(map[int]string)
	timeout := 2 * time.Second
	port_list := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80}
	for _, port := range port_list {
		address := ip + ":" + fmt.Sprintf("%d", port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {

			portStatuses[port] = "Closed/Filtered"
			continue
		}

	portStatuses[port] = "Open"
	// Ensure we explicitly handle the Close() error to satisfy linters
	_ = conn.Close() // Close only when connection is successful

	}
	return portStatuses
}
