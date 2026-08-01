package main

import (
	"argus/internal/seccomp"
	"fmt"
	"os"
	"syscall"
)

func main() {
	fmt.Println("argus-exec helper started")

	fmt.Println("Args:", os.Args)

	if len(os.Args) < 4 {
		fmt.Println("Usage: argus-exec <profile> <program> <script>")
		os.Exit(1)
	}

	profile := os.Args[1]
	program := os.Args[2]
	script := os.Args[3]

	fmt.Println("Profile:", profile)
	fmt.Println("Program:", program)
	fmt.Println("Script:", script)

	if err := seccomp.ApplyProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, "apply seccomp profile: %v\n", err)
		os.Exit(1)
	}

	err := syscall.Exec(program, []string{program, script}, os.Environ())
	if err != nil {
		fmt.Println("Failed to exec program:", err)
		os.Exit(1)
	}
}
