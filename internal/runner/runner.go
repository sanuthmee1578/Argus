package runner

import (
	"context"
	"fmt"
	"os/exec"
	"time"
	"bytes"
)

func Run(script string, timeout time.Duration) (string, string, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "python3", script)

	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	err := cmd.Start()
	if err != nil {
		fmt.Println("Error starting Script:", err)
		return "ERROR", "", time.Since(startTime)
	}

	pid := cmd.Process.Pid
	fmt.Println("Script PID:", pid)

	err = cmd.Wait()

	output := outputBuffer.String()

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("Script execution timed out")
		return "TIMEOUT", string(output), time.Since(startTime)
	} else if err != nil {
		fmt.Println("Error executing Script:", err)
		return "ERROR", string(output), time.Since(startTime)
	}

	sinceTime := time.Since(startTime)
	return "SUCCESS", string(output), sinceTime
}