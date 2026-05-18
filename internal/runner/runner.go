package runner

import (
	"argus/internal/monitor"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

func Run(script string, timeout time.Duration) (string, string, time.Duration, int, time.Time, time.Time, map[string]string) {
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
		return "ERROR", "", time.Since(startTime), 0, startTime, endTime, map[string]string{}
	}

	pid := cmd.Process.Pid

	fmt.Println("Script PID:", pid)

	monitorResults := monitor.ReadStatus(pid)
	fmt.Println("Initial Monitor Results:", monitorResults)

	err = cmd.Wait()

	endTime := time.Now()

	output := outputBuffer.String()

	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("Script execution timed out")
		return "TIMEOUT", string(output), time.Since(startTime), pid, startTime, endTime, monitorResults
	} else if err != nil {
		fmt.Println("Error executing Script:", err)
		return "ERROR", string(output), time.Since(startTime), pid, startTime, endTime, monitorResults
	}

	sinceTime := time.Since(startTime)
	return "SUCCESS", string(output), sinceTime, pid, startTime, endTime, monitorResults
}
