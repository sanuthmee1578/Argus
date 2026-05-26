package runner

import (
	"argus/internal/monitor"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
	"syscall"
)

func Run(script string, timeout time.Duration, memoryLimitMB int) (string, string, time.Duration, int, time.Time, time.Time, map[string]string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "python3", script)

	cmd.Dir = "sandbox/test1"

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
    }

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

	done := make(chan struct{})

	memoryExceededChan := make(chan struct{})

	monitorResultsChan := make(chan map[string]string)

	go func() {
		monitorResultsChan <- monitor.PollStatus(pid, 100*time.Millisecond, done, memoryLimitMB, memoryExceededChan)
	}()

	fmt.Println("Script PID:", pid)

	waitChan := make(chan error)

	go func() {
		waitChan <- cmd.Wait()
	}()

	

	select {
	case err = <-waitChan:
		// process finished normally

	case <-memoryExceededChan:
		// kill process
		syscall.Kill(-pid, syscall.SIGKILL)
		err = <-waitChan

	case <-ctx.Done():
    syscall.Kill(-pid, syscall.SIGKILL)
    err = <-waitChan
	
	}

	close(done)

	monitorResults := <-monitorResultsChan

	endTime := time.Now()

	output := outputBuffer.String()

	if monitorResults["MemoryExceeded"] == "true" {
		fmt.Println("Memory limit exceeded")
		return "MEMORY_LIMIT_EXCEEDED", output, time.Since(startTime), pid, startTime, endTime, monitorResults
	}

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
