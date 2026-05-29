package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

func main() {
	root := "/tmp/argus-root"

	err := syscall.Chroot(root)
	if err != nil {
		fmt.Println("chroot failed:", err)
		return
	}

	err = syscall.Chdir("/")
	if err != nil {
		fmt.Println("chdir failed:", err)
		return
	}

	cmd := exec.Command("/bin/hello_chroot")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("execution failed:", err)
		return
	}

	fmt.Println(string(output))

}
