package runner

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func Run(script string) (string, string, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "python3", script)

	output, err := cmd.CombinedOutput()

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