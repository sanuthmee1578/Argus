package main

import (
	"argus/internal/logger"
	"argus/internal/policy"
	"argus/internal/runner"
	"argus/internal/scanner"
	"argus/internal/behavior"
	"fmt"
	"os"
	"time"
)

func main() {

	// Check if enough arguments are provided
	if len(os.Args) < 3 {
		fmt.Println("Usage: argus run <script>")
		return
	}

	// Extract the command and script from the arguments
	command := os.Args[1]
	script := os.Args[2]

	if command != "run" {
		fmt.Println("Unknown command:", command)
		return
	}

	if _, err := os.Stat(script); os.IsNotExist(err) {
		fmt.Println("Script not found:", script)
		return
	}

	loadPolicy := policy.Load()

	warnings := scanner.Scan(loadPolicy.BlockedPatterns, script)

	analysis := behavior.Analyze(warnings)

	// Print the command and script for debugging purposes
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)

	if len(warnings) > 0 {
		if loadPolicy.StrictMode {
			fmt.Println("⚠ Strict mode enabled. Execution blocked due to suspicious patterns.")
			logger.Write(script, "BLOCKED_BY_POLICY", "Script blocked due to strict mode.", warnings, time.Duration(0), 0, time.Time{}, time.Time{}, map[string]string{}, analysis)
			return
		} else {
			var choice string
			fmt.Println("⚠ Suspicious patterns detected in the script. Do you want to proceed? (y/n)")
			fmt.Scanln(&choice)
			if choice != "y" {
				fmt.Println("BLOCKED_BY_USER")
				fmt.Println("⚠ Warning:")
				for _, warning := range warnings {
					fmt.Println("-", warning)
				}

				err := logger.Write(script, "BLOCKED_BY_USER", "Execution aborted by the user.", warnings, time.Duration(0), 0, time.Time{}, time.Time{}, map[string]string{}, analysis)
				if err != nil {
					fmt.Println("Error writing log:", err)
				}
				return

			} else if choice == "y" {
				fmt.Println("Proceeding with execution...")
				fmt.Println("⚠ Warning:")
				for _, warning := range warnings {
					fmt.Println("-", warning)
				}
			}
		}
	}
	timeout := time.Duration(loadPolicy.Timeout) * time.Second
	status, output, duration, pid, startTime, endTime, monitorResults := runner.Run(script, timeout, loadPolicy.MemoryLimitMB)
	err := logger.Write(script, status, output, warnings, duration, pid, startTime, endTime, monitorResults, analysis)
	if err != nil {
		fmt.Println("Error writing log:", err)
		return
	}
	fmt.Println("Status:", status)
	fmt.Println("Output:", output)
	fmt.Printf("Execution time: %v\n", duration)
}
