package cgroup

import (
	"os"
	"path/filepath"
	"strconv"
)

func Create(runID string, memoryLimitMB int) (string, error) {
	cgroupPath := filepath.Join("/sys/fs/cgroup", "argus-"+runID)

	err := os.MkdirAll(cgroupPath, 0755)
	if err != nil {
		return "", err
	}

	memoryBytes := memoryLimitMB * 1024 * 1024
	memoryMaxPath := filepath.Join(cgroupPath, "memory.max")

	err = os.WriteFile(memoryMaxPath, []byte(strconv.Itoa(memoryBytes)), 0644)
	if err != nil {
		return "", err
	}

	return cgroupPath, nil
}

func Attach(cgroupPath string, pid int) error {
	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")
	return os.WriteFile(cgroupProcsPath, []byte(strconv.Itoa(pid)), 0644)
}
