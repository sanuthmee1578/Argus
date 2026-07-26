package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

type Policy struct {
	Timeout    int  `json:"timeout"`
	StrictMode bool `json:"strict_mode"`

	BlockedPatterns []string `json:"blocked_patterns"`

	MemoryLimitMB int `json:"memory_limit_mb"`
	PidsLimit     int `json:"pids_limit"`
	CPUQuota      int `json:"cpu_quota"`
	CPUPeriod     int `json:"cpu_period"`

	KeepSandbox bool `json:"keep_sandbox"`

	RootfsPath string `json:"rootfs_path"`

	EnableChroot bool `json:"enable_chroot"`

	EnableSeccomp  bool   `json:"enable_seccomp"`
	SeccompProfile string `json:"seccomp_profile"`
}

func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("error reading policy file: %w", err)
	}

	var loadedPolicy Policy

	if err := json.Unmarshal(data, &loadedPolicy); err != nil {
		return Policy{}, fmt.Errorf("error parsing policy file: %w", err)
	}

	return loadedPolicy, nil
}
