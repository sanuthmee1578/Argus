package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func Create(runID string, memoryLimitMB int, pidsLimit int, cpuQuota int, cpuPeriod int) (string, error) {
	return CreateAt(
		"/sys/fs/cgroup",
		runID,
		memoryLimitMB,
		pidsLimit,
		cpuQuota,
		cpuPeriod,
	)
}

func CreateAt(
	basePath string,
	runID string,
	memoryLimitMB int,
	pidsLimit int,
	cpuQuota int,
	cpuPeriod int,
) (string, error) {
	if err := validateRunID(runID); err != nil {
		return "", err
	}

	if memoryLimitMB <= 0 {
		return "", fmt.Errorf("memory limit must be greater than zero")
	}
	if pidsLimit <= 0 {
		return "", fmt.Errorf("PID limit must be greater than zero")
	}
	if cpuQuota <= 0 {
		return "", fmt.Errorf("CPU quota must be greater than zero")
	}
	if cpuPeriod <= 0 {
		return "", fmt.Errorf("CPU period must be greater than zero")
	}

	cgroupPath := filepath.Join(basePath, "argus-"+runID)

	if err := os.Mkdir(cgroupPath, 0755); err != nil {
		return "", fmt.Errorf("create cgroup directory: %w", err)
	}

	setupComplete := false
	defer func() {
		if !setupComplete {
			_ = os.RemoveAll(cgroupPath)
		}
	}()

	memoryBytes := int64(memoryLimitMB) * 1024 * 1024

	if err := os.WriteFile(
		filepath.Join(cgroupPath, "memory.max"),
		[]byte(strconv.FormatInt(memoryBytes, 10)),
		0644,
	); err != nil {
		return "", fmt.Errorf("write memory.max: %w", err)
	}

	if err := os.WriteFile(
		filepath.Join(cgroupPath, "pids.max"),
		[]byte(strconv.Itoa(pidsLimit)),
		0644,
	); err != nil {
		return "", fmt.Errorf("write pids.max: %w", err)
	}

	cpuMaxValue := fmt.Sprintf("%d %d", cpuQuota, cpuPeriod)

	if err := os.WriteFile(
		filepath.Join(cgroupPath, "cpu.max"),
		[]byte(cpuMaxValue),
		0644,
	); err != nil {
		return "", fmt.Errorf("write cpu.max: %w", err)
	}

	setupComplete = true
	return cgroupPath, nil
}

func validateRunID(runID string) error {
	if runID == "" || runID == "." || runID == ".." {
		return fmt.Errorf("invalid run ID %q", runID)
	}

	if filepath.IsAbs(runID) {
		return fmt.Errorf("run ID must not be an absolute path: %q", runID)
	}

	if filepath.Base(runID) != runID {
		return fmt.Errorf("run ID must not contain path components: %q", runID)
	}

	return nil
}

func Attach(cgroupPath string, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("PID must be greater than zero")
	}

	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")

	if err := os.WriteFile(
		cgroupProcsPath,
		[]byte(strconv.Itoa(pid)),
		0644,
	); err != nil {
		return fmt.Errorf("attach PID %d to cgroup: %w", pid, err)
	}

	return nil
}

func Cleanup(cgroupPath string) error {
	if err := os.Remove(cgroupPath); err != nil {
		return fmt.Errorf("remove cgroup %q: %w", cgroupPath, err)
	}

	return nil
}
