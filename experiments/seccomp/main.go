package main

import (
	"argus/internal/seccomp"
	"fmt"
	"syscall"
)

func main() {
	fmt.Println("Applying seccomp profile...")

	err := seccomp.ApplyDefaultProfile()
	if err != nil {
		fmt.Println("seccomp failed:", err)
		return
	}

	fmt.Println("Trying reboot syscall...")

	_, _, errno := syscall.Syscall(
		syscall.SYS_REBOOT,
		0,
		0,
		0,
	)

	fmt.Println("errno:", errno)
}
