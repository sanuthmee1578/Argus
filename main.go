package main

import (
	"fmt"
	"os"
	"argus/internal/runner"
	"argus/internal/logger"
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

	// Print the command and script for debugging purposes
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)

	if command != "run" {
		fmt.Println("Unknown command:",command)
		return
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