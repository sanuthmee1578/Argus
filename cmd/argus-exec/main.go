package main

import (
	"argus/internal/seccomp"
	"fmt"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(
			os.Stderr,
			"usage: argus-exec <profile> <program> <script>",
		)
		os.Exit(1)
	}

	profile := os.Args[1]
	program := os.Args[2]
	script := os.Args[3]

	if err := seccomp.ApplyProfile(profile); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"apply seccomp profile %q: %v\n",
			profile,
			err,
		)
		os.Exit(1)
	}

	if err := syscall.Exec(
		program,
		[]string{program, script},
		os.Environ(),
	); err != nil {
		fmt.Fprintf(os.Stderr, "execute %q: %v\n", program, err)
		os.Exit(1)
	}
}
