package cgroup

import (
	"os"
	"path/filepath"
)

func Create(runID string) (string, error) {
	cgroupPath := filepath.Join("/sys/fs/cgroup", "argus-"+runID)

	err := os.MkdirAll(cgroupPath, 0755)
	if err != nil {
		return "", err
	}

	return cgroupPath, nil
}
