package main

import (
	"fmt"
	"os"
	"argus/internal/runner"
	"argus/internal/logger"
	"argus/internal/scanner"
	"argus/internal/policy"
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
		fmt.Println("Unknown command:",command)
		return
	}

	if _, err := os.Stat(script); os.IsNotExist(err) {
		fmt.Println("Script not found:", script)
		return
   }

   loadPolicy := policy.Load()
   warnings := scanner.Scan(loadPolicy.BlockedPatterns, script)

	// Print the command and script for debugging purposes
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)

	if len(warnings) > 0 {
		if(loadPolicy.StrictMode){
			fmt.Println("⚠ Strict mode enabled. Execution blocked due to suspicious patterns.")
			logger.Write(script, "BLOCKED_BY_POLICY", "Script blocked due to strict mode.", warnings)
			return
		}else {
			var choice string
			fmt.Println("⚠ Suspicious patterns detected in the script. Do you want to proceed? (y/n)")
			fmt.Scanln(&choice)
			if(choice != "y"){
				fmt.Println("BLOCKED_BY_USER")
				fmt.Println("⚠ Warning:")
				for _, warning := range warnings {
					fmt.Println("-", warning)
				}

				err := logger.Write(script, "BLOCKED_BY_USER", "Execution aborted by the user.", warnings)
					if err != nil {
					fmt.Println("Error writing log:", err)
				}
				return

			}else if choice == "y" {
				fmt.Println("Proceeding with execution...")
				fmt.Println("⚠ Warning:")
				for _, warning := range warnings {
					fmt.Println("-", warning)
				}
			} 
		}
	}
	status, output,duration := runner.Run(script)
				err := logger.Write(script, status, output, warnings)
				if err != nil {
					fmt.Println("Error writing log:", err)
					return
				}
				fmt.Println("Status:", status)
				fmt.Println("Output:", output)
				fmt.Printf("Execution time: %v\n", duration)
}