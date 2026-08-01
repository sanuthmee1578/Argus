package runner

import (
	"argus/internal/cgroup"
	"argus/internal/monitor"
	"argus/internal/sandbox"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func Run(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	startTime := time.Now()
	runID := strconv.FormatInt(time.Now().UnixNano(), 10)

	prepared, err := sandbox.PrepareSandbox(script, enableChroot, rootfsPath)
	if err != nil {
		endTime := time.Now()
		return Result{
			RunID:          runID,
			Status:         "ERROR",
			ErrorMessage:   fmt.Sprintf("prepare sandbox: %v", err),
			Duration:       time.Since(startTime),
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: map[string]string{},
			SandboxKept:    keepSandbox,
		}
	}

	if !keepSandbox {
		defer os.RemoveAll(prepared.HostPath)
	}

	helperPath, err := filepath.Abs("bin/argus-exec")
	if err != nil {
		endTime := time.Now()
		return Result{
			RunID:          runID,
			Status:         "ERROR",
			ErrorMessage:   fmt.Sprintf("resolve argus-exec path: %v", err),
			Duration:       time.Since(startTime),
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: map[string]string{},
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}
	var cmd *exec.Cmd

	if enableChroot {
		if enableSeccomp {
			cmd = exec.CommandContext(
				ctx,
				"/usr/local/bin/argus-exec",
				seccompProfile,
				"/usr/bin/python3",
				prepared.ScriptName,
			)
		} else {
			cmd = exec.CommandContext(
				ctx,
				"/usr/bin/python3",
				prepared.ScriptName,
			)
		}

		cmd.Dir = prepared.RuntimePath
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			Chroot:  rootfsPath,
			Cloneflags: syscall.CLONE_NEWNS |
				syscall.CLONE_NEWPID |
				syscall.CLONE_NEWNET,
		}
	} else {
		if enableSeccomp {
			cmd = exec.CommandContext(
				ctx,
				helperPath,
				seccompProfile,
				"/usr/bin/python3",
				prepared.ScriptName,
			)
		} else {
			cmd = exec.CommandContext(
				ctx,
				"/usr/bin/python3",
				prepared.ScriptName,
			)
		}

		cmd.Dir = prepared.RuntimePath
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}
	}

	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &outputBuffer

	cgroupPath, err := cgroup.Create(
		runID,
		memoryLimitMB,
		pidsLimit,
		cpuQuota,
		cpuPeriod,
	)

	if err != nil {
		endTime := time.Now()
		return Result{
			RunID:          runID,
			Status:         "ERROR",
			ErrorMessage:   fmt.Sprintf("create cgroup: %v", err),
			Duration:       time.Since(startTime),
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: map[string]string{},
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}

	defer func() {
		_ = cgroup.Cleanup(cgroupPath)
	}()

	cgroupDir, err := os.Open(cgroupPath)
	if err != nil {
		endTime := time.Now()
		return Result{
			RunID:          runID,
			Status:         "ERROR",
			ErrorMessage:   fmt.Sprintf("open cgroup for process placement: %v", err),
			Duration:       time.Since(startTime),
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: map[string]string{},
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}
	defer cgroupDir.Close()

	configureCgroupPlacement(cmd, cgroupDir)

	err = cmd.Start()
	if err != nil {
		endTime := time.Now()
		return Result{
			RunID:          runID,
			Status:         "ERROR",
			ErrorMessage:   fmt.Sprintf("start script: %v", err),
			Duration:       time.Since(startTime),
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: map[string]string{},
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}

	pid := cmd.Process.Pid

	done := make(chan struct{})

	memoryExceededChan := make(chan struct{}, 1)

	monitorResultsChan := make(chan map[string]string)

	go func() {
		monitorResultsChan <- monitor.PollStatus(pid, 100*time.Millisecond, done, memoryLimitMB, memoryExceededChan)
	}()

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
		return Result{
			RunID:          runID,
			Status:         "MEMORY_LIMIT_EXCEEDED",
			Output:         output,
			Duration:       time.Since(startTime),
			PID:            pid,
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: monitorResults,
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}

	if ctx.Err() == context.DeadlineExceeded {
		return Result{
			RunID:          runID,
			Status:         "TIMEOUT",
			Output:         output,
			ErrorMessage:   fmt.Sprintf("Execution exceeded the %s limit", timeout),
			Duration:       time.Since(startTime),
			PID:            pid,
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: monitorResults,
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	} else if err != nil {
		if isSeccompNetworkViolation(output, enableSeccomp, seccompProfile) {
			return Result{
				RunID:          runID,
				Status:         "SECURITY_VIOLATION",
				Output:         output,
				ErrorMessage:   "Network syscall blocked by seccomp",
				Duration:       time.Since(startTime),
				PID:            pid,
				StartTime:      startTime,
				EndTime:        endTime,
				MonitorResults: monitorResults,
				SandboxPath:    prepared.HostPath,
				SandboxKept:    keepSandbox,
			}
		}

		return Result{
			RunID:          runID,
			Status:         "ERROR",
			Output:         output,
			ErrorMessage:   fmt.Sprintf("execute script: %v", err),
			Duration:       time.Since(startTime),
			PID:            pid,
			StartTime:      startTime,
			EndTime:        endTime,
			MonitorResults: monitorResults,
			SandboxPath:    prepared.HostPath,
			SandboxKept:    keepSandbox,
		}
	}

	sinceTime := time.Since(startTime)
	return Result{
		RunID:          runID,
		Status:         "SUCCESS",
		Output:         output,
		Duration:       sinceTime,
		PID:            pid,
		StartTime:      startTime,
		EndTime:        endTime,
		MonitorResults: monitorResults,
		SandboxPath:    prepared.HostPath,
		SandboxKept:    keepSandbox,
	}
}

func isSeccompNetworkViolation(output string, enableSeccomp bool, seccompProfile string) bool {
	if !enableSeccomp || seccompProfile != "no-network" {
		return false
	}

	normalizedOutput := strings.ToLower(output)
	return strings.Contains(normalizedOutput, "permissionerror") &&
		strings.Contains(normalizedOutput, "operation not permitted")
}

func configureCgroupPlacement(cmd *exec.Cmd, cgroupDir *os.File) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(cgroupDir.Fd())
}
