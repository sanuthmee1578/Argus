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
	childHistory := map[string]ChildProcessDetails{} // Track all children ever seen

	for {
		select {
		case <-done:
			// Step 2: Include full process history in results
			var historyList []string
			for _, child := range childHistory {
				historyList = append(historyList, child.PID+" "+child.Name+" "+child.Command)
			}

			return map[string]string{
				"PeakVmRSS":      peakVmRSS,
				"MemoryExceeded": strconv.FormatBool(memoryExceeded),
				"ChildProcesses": strings.Join(childProcesses, ", "),
				"ChildHistory":   strings.Join(historyList, " | "),
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
					// Step 2: Track all children ever seen (history)
					childHistory[child.PID] = child
				}
				childProcesses = details
			}

			for _, child := range childDetails {
				// Step 3: Check both process name and command pattern for suspicious behavior
				if IsSuspiciousProcess(child.Name, child.Command) {
					label := child.Name + "(PID:" + child.PID + ") cmd:" + child.Command

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

func IsSuspiciousProcess(name string, command string) bool {
	// Step 3a: Check process name against suspicious list
	suspiciousNames := map[string]bool{
		"bash": true,
		"sh":   true,
		"curl": true,
		"wget": true,
		"nc":   true,
	}

	if suspiciousNames[name] {
		return true
	}

	// Step 3b: Check command line for suspicious patterns
	if IsSuspiciousCommand(command) {
		return true
	}

	return false
}

func IsSuspiciousCommand(command string) bool {
	// Check for common suspicious command patterns
	suspiciousPatterns := []string{
		"bash -c",
		"sh -c",
		"python -c",
		"python3 -c",
		"perl -e",
		"ruby -e",
		"/bin/bash -c",
		"/bin/sh -c",
		"|",      // Piping to shell
		";",      // Command chaining
		"curl",   // Download and execute
		"wget",   // Download and execute
		"nc ",    // Netcat
		"ncat",   // Netcat
		"/dev/tcp", // Bash network redirection
		"/dev/udp", // Bash network redirection
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}

	return false
}