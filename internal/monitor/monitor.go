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

func PollStatus(pid int, interval time.Duration, done <-chan struct{}, memoryLimitMB int, memoryExceededChan chan<- struct{}) map[string]string {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	peakVmRSS := "0 kB"
	memoryExceeded := false
	alertSent := false
	childProcesses := []string{}
	suspiciousProcesses := []string{}
	seenSuspicious := map[string]bool{}

	for {
		select {
		case <-done:
			return map[string]string{
				"PeakVmRSS":      peakVmRSS,
				"MemoryExceeded": strconv.FormatBool(memoryExceeded),
				"ChildProcesses": strings.Join(childProcesses, ", "),
				"SuspiciousChildProcesses": strings.Join(suspiciousProcesses, ", "),
			}

		case <-ticker.C:
			status := ReadStatus(pid)
			current := status["VmRSS"]

			if current != "" {
				fields := strings.Fields(current)
				memory := fields[0]
				memoryInt, err := strconv.Atoi(memory)
				if err != nil {
					fmt.Println("Error converting memory usage:", err)
					continue
				}

				peakFields := strings.Fields(peakVmRSS)
				peakMemory := peakFields[0]
				peakInt, err := strconv.Atoi(peakMemory)

				if err != nil {
					fmt.Println("Error converting peak memory usage:", err)
					continue
				}

				if memoryInt > peakInt {
					peakVmRSS = current
				}

				if memoryInt > memoryLimitMB*1024 {
					memoryExceeded = true
					if !alertSent {
						memoryExceededChan <- struct{}{}
						alertSent = true
					}
				}

			}

			children := ReadChildren(pid)

			if len(children) > 0 {
				childProcesses = children
			}

			for _, child := range children {
				name := ReadProcessName(child)
				if IsSuspiciousProcess(name) {
					label := name + "(PID:" + child + ")"

					if !seenSuspicious[label] {
						suspiciousProcesses = append(suspiciousProcesses, label)
						seenSuspicious[label] = true
					}
				}
		}

		
	}
	
	}

}

func ReadChildren(pid int) []string {
    children := []string{}
	path := "/proc/" + strconv.Itoa(pid) + "/task/" + strconv.Itoa(pid) + "/children"
	data, err := os.ReadFile(path)
	if err != nil {
		return children
	}
	children = strings.Fields(string(data))

    return children
}

func ReadProcessName(pid string) string{
	path := "/proc/" + pid + "/comm"
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading process name:", err)
		return ""
	}
	return strings.TrimSpace(string(data))

}

func IsSuspiciousProcess(name string) bool{
	suspiciousProcesses := map[string]bool{
		"bash": true,
		"sh": true,
		"curl": true,
		"wget": true,
		"nc": true,
    }

	return suspiciousProcesses[name]
}