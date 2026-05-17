package runner

import (
	"context"
	"fmt"
	"os/exec"
	"time"
	"bytes"
)

func Run(script string, timeout time.Duration) (string, string, time.Duration, int, time.Time, time.Time) {
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
		endTime := time.Now()
		return "ERROR", "", time.Since(startTime),0, startTime, endTime
	}

	pid := cmd.Process.Pid
	
	fmt.Println("Script PID:", pid)

	err = cmd.Wait()

	endTime := time.Now()

	output := outputBuffer.String()

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("Script execution timed out")
		return "TIMEOUT", string(output), time.Since(startTime),pid, startTime, endTime
	} else if err != nil {
		fmt.Println("Error executing Script:", err)
		return "ERROR", string(output), time.Since(startTime),pid, startTime, endTime
	}

	sinceTime := time.Since(startTime)
	return "SUCCESS", string(output), sinceTime,pid, startTime, endTime
}