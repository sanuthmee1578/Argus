package main

import (
	"fmt"
	"os"
)

func main() {

	// Check if enough arguments are provided
	if len(os.Args) < 3 {
		fmt.Println("Usage: argus run <script>")
		return
	}

	// Extract values
	command := os.Args[1]
	script := os.Args[2]

	// Print them
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)
}