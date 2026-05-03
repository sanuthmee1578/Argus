package main

import (
	"fmt"
	"os"
	"os/exec"
	"context"
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

	// Print the command and script for debugging purposes
	fmt.Println("Command:", command)
	fmt.Println("Script:", script)

	if command != "run" {
		fmt.Println("Unknown command:",command)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python3", script)

	
	output, err := cmd.CombinedOutput()

	var success string

	if (ctx.Err() == context.DeadlineExceeded) {
		fmt.Println("Script execution timed out")
		success = "Timed out"
	}else if err !=nil {
		fmt.Println("Error executing Script:", err)
		success = "Error"
	}else{
		success = "Success"
		fmt.Println(string(output))
	}

	log := "\nScript:" + script + "\nStatus: " + success + "\nOutput:" + string(output)

	err = os.WriteFile("./logs/latest.log", []byte(log), 0644)
	if err != nil {
		fmt.Println("Error writing to log file:", err)
		return
	}

	fmt.Println("Log written to file:", "./logs/latest.log")
}