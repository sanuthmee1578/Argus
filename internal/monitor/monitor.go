package monitor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func ReadStatus(pid int) map[string]string {
	results := map[string]string{}

	pidString := strconv.Itoa(pid)
	path := "/proc/" + pidString + "/status"

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading process status:", err)
		return results
	}

	lines := strings.Split(string(data), "\n")

	fieldsToRead := map[string]bool{
		"State:":   true,
		"VmRSS:":   true,
		"Threads:": true,
	}

	for _, line := range lines {
		for field := range fieldsToRead {
			if strings.HasPrefix(line, field) {
				parts := strings.SplitN(line, ":\t", 2)
				if len(parts) == 2 {
					key := field[:len(field)-1]
					results[key] = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}

	return results
}

func PollStatus(pid int, interval time.Duration, done <-chan struct{}, memoryLimitMB int) map[string]string {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	peakVmRSS := "0 kB"
	memoryExceeded := false

	for {
		select {
		case <-done:
			return map[string]string{
				"PeakVmRSS":      peakVmRSS,
				"MemoryExceeded": strconv.FormatBool(memoryExceeded),
			}

		case <-ticker.C:
			status := ReadStatus(pid)
			current := status["VmRSS"]

			if current != "" {
				peakVmRSS = current
				fields := strings.Fields(current)
				memory := fields[0]
				memoryInt, err := strconv.Atoi(memory)
				if err != nil {
					fmt.Println("Error converting memory usage:", err)
					continue
				}

				if memoryInt > memoryLimitMB*1024 {
					memoryExceeded = true
				}

			}

		}

	}

}
