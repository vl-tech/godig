package dns_checks

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var wg sync.WaitGroup

// CheckOpenPorts scans a predefined list of common server ports and returns their open/closed status
func CheckOpenPorts(ip string) map[int]string {

	portStatuses := make(map[int]string)
	mu := &sync.Mutex{}
	timeout := 3 * time.Second
	port_list := []int{22, 21, 25, 53, 2525, 993, 143, 995, 110, 587, 2087, 3306, 2083, 2096, 443, 80, 2078, 2079, 2086, 465, 8443, 8080, 5432}
	for _, port := range port_list {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := ip + ":" + fmt.Sprintf("%d", p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			mu.Lock()
			if err != nil {
				portStatuses[p] = "Closed/Filtered"
			} else {
				portStatuses[p] = "Open"
				// Ensure we explicitly handle the Close() error to satisfy linters
				_ = conn.Close() // Close only when connection is successful
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return portStatuses
}
