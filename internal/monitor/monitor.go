package monitor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type ChildProcessDetails struct {
	PID     string
	Name    string
	Command string
}

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

			childDetails := ReadChildrenDetails(pid)

			if len(childDetails) > 0 {
				var details []string
				for _, child := range childDetails {
					details = append(details, child.PID+" "+child.Name+" "+child.Command)
				}
				childProcesses = details
			}

			for _, child := range childDetails {
				if IsSuspiciousProcess(child.Name) {
					label := child.Name + "(PID:" + child.PID + ")"

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

func ReadProcessName(pid string) string {
	path := "/proc/" + pid + "/comm"
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ReadProcessCommand(pid string) string {
	path := "/proc/" + pid + "/cmdline"
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// cmdline has null-separated arguments, replace with spaces
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline)
}

func ReadChildrenDetails(pid int) []ChildProcessDetails {
	details := []ChildProcessDetails{}
	pidStrings := ReadChildren(pid)

	for _, pidStr := range pidStrings {
		name := ReadProcessName(pidStr)
		command := ReadProcessCommand(pidStr)
		details = append(details, ChildProcessDetails{
			PID:     pidStr,
			Name:    name,
			Command: command,
		})
	}

	return details
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