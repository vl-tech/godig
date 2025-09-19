package dns_checks


import (
	"time"
	"fmt"
	"net"
	
)
func CheckOpenPorts(ip string) map[int]string {

	portStatuses := make(map[int]string)
	timeout := 2 * time.Second
	port_list := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80}
	for _, port := range port_list {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "Port\t%d is closed:\n", port)
			portStatuses[port] = "Closed/Filtered"
			continue
		}
		// t.Printf("Port\t%d is open\n", port)
		portStatuses[port] = "Open"
		conn.Close() // Close only when connection is successful

	}
	return portStatuses
}
