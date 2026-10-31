package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

func ResolveDefaultPolicyPath() (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate Argus executable: %w", err)
	}

	return resolvePolicyFromDir(filepath.Dir(executablePath))
}

func resolvePolicyFromDir(executableDir string) (string, error) {
	candidates := []string{
		filepath.Join(executableDir, "config", "policy.json"),
		filepath.Join(executableDir, "..", "config", "policy.json"),
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("default policy.json not found near Argus executable")
}
