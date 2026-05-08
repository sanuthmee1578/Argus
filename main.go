package main

import (
	"fmt"
	"os"
	"argus/internal/runner"
	"argus/internal/logger"
	"argus/internal/scanner"
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

	if _, err := os.Stat(script); os.IsNotExist(err) {
		fmt.Println("Script not found:", script)
		return
   }
   warnings := scanner.Scan(script)

	// Print the command and script for debugging purposes
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)

	if len(warnings) > 0 {
		var choice string
		fmt.Println("⚠ Suspicious patterns detected in the script. Do you want to proceed? (y/n)")
		fmt.Scanln(&choice)
		if(choice != "y"){
			fmt.Println("Execution aborted by the user.")
			fmt.Println("⚠ Warning:")
			for _, warning := range warnings {
				fmt.Println("-", warning)
			}
			return
		}else if choice == "y" {
			fmt.Println("Proceeding with execution...")
			fmt.Println("⚠ Warning:")
			for _, warning := range warnings {
				fmt.Println("-", warning)
			}
			status, output := runner.Run(script)
			err := logger.Write(script, status, output)
			if err != nil {
				fmt.Println("Error writing log:", err)
				return
			}
			fmt.Println("Status:", status)
			fmt.Println("Output:", output)
		} 

		
	}

	if command != "run" {
		fmt.Println("Unknown command:",command)
		return
	}

	
}