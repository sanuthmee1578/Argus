package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var procRoot = "/proc"

type ChildProcessDetails struct {
	PID     string
	Name    string
	Command string
}

func ReadStatus(pid int) map[string]string {
	results := map[string]string{}

	pidString := strconv.Itoa(pid)
	path := filepath.Join(procRoot, pidString, "status")

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
	seenSuspicious := map[string]bool{}              // Key: PID+Name for stable deduplication
	suspiciousDetails := map[string]string{}         // Key: PID+Name, Value: full label with command
	childHistory := map[string]ChildProcessDetails{} // Track all children ever seen

	for {
		select {
		case <-done:
			// Step 2: Include full process history in results
			var historyList []string
			for _, child := range childHistory {
				historyList = append(historyList, child.PID+" "+child.Name+" "+child.Command)

				// Also check history against suspicious detection for processes that may have exited
				if IsSuspiciousProcess(child.Name, child.Command) {
					dedupKey := child.PID + ":" + child.Name

					if !seenSuspicious[dedupKey] {
						label := child.Name + "(PID:" + child.PID + ") cmd:" + child.Command
						suspiciousDetails[dedupKey] = label
						seenSuspicious[dedupKey] = true
					}
				}
			}

			// Build final suspicious list from cached details
			for _, label := range suspiciousDetails {
				suspiciousProcesses = append(suspiciousProcesses, label)
			}

			return map[string]string{
				"PeakVmRSS":                peakVmRSS,
				"MemoryExceeded":           strconv.FormatBool(memoryExceeded),
				"ChildProcesses":           strings.Join(childProcesses, ", "),
				"ChildHistory":             strings.Join(historyList, " | "),
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
					// Use cached command from history if available (in case process is exiting)
					command := child.Command
					if cachedChild, exists := childHistory[child.PID]; exists {
						command = cachedChild.Command
					}
					details = append(details, child.PID+" "+child.Name+" "+command)

					// Step 2: Track all children ever seen (history)
					// Only add/update if this PID wasn't seen before, preserving command even after process exits
					if _, exists := childHistory[child.PID]; !exists {
						childHistory[child.PID] = child
					}
				}
				childProcesses = details
			}

			for _, child := range childDetails {
				// Step 3: Check both process name and command pattern for suspicious behavior
				if IsSuspiciousProcess(child.Name, child.Command) {
					dedupKey := child.PID + ":" + child.Name // Use PID+Name as stable key

					if !seenSuspicious[dedupKey] {
						label := child.Name + "(PID:" + child.PID + ") cmd:" + child.Command
						suspiciousDetails[dedupKey] = label
						seenSuspicious[dedupKey] = true
					}
				}
			}

		}

	}

}

func ReadChildren(pid int) []string {
	children := []string{}
	pidString := strconv.Itoa(pid)
	path := filepath.Join(procRoot, pidString, "task", pidString, "children")
	data, err := os.ReadFile(path)
	if err != nil {
		return children
	}
	children = strings.Fields(string(data))

	return children
}

func ReadProcessName(pid string) string {
	path := filepath.Join(procRoot, pid, "comm")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ReadProcessCommand(pid string) string {
	path := filepath.Join(procRoot, pid, "cmdline")
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
		"curl",     // Download and execute
		"wget",     // Download and execute
		"nc ",      // Netcat
		"ncat",     // Netcat
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
