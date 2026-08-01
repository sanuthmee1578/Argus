package cli

import (
	"argus/internal/policy"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func RunClean(
	out io.Writer,
	errOut io.Writer,
	policyPath string,
) int {
	printSection(out, "Argus cleanup")

	loadedPolicy, err := policy.Load(policyPath)
	if err != nil {
		printStep(out, false, "Policy configuration loaded")
		fmt.Fprintf(errOut, "policy load failed: %v\n", err)
		return ExitGeneralError
	}

	failed := false

	removed, err := removeHostSandbox()
	if err != nil {
		failed = true
		printStep(out, false, "Removed stale host sandbox directories")
		fmt.Fprintf(errOut, "clean /tmp/argus: %v\n", err)
	}

	rootfsRemoved, err := removeRootfsSandboxes(loadedPolicy.RootfsPath)
	if err != nil {
		failed = true
		printStep(out, false, "Removed stale rootfs sandbox directories")
		fmt.Fprintf(errOut, "clean rootfs sandboxes: %v\n", err)
	} else {
		totalRemoved := removed + rootfsRemoved
		printStep(out, true, fmt.Sprintf("Removed %d stale sandbox directories", totalRemoved))
	}

	staleCgroups, err := countStaleCgroups()
	if err != nil {
		failed = true
		printStep(out, false, "Checked stale cgroups")
		fmt.Fprintf(errOut, "check stale cgroups: %v\n", err)
	}
	if staleCgroups == 0 {
		printStep(out, true, "No stale cgroups found")
	} else if err == nil {
		failed = true
		printStep(out, false, fmt.Sprintf("%d stale cgroup(s) found", staleCgroups))
	}

	printStep(out, true, "Reports preserved")

	if failed {
		return ExitGeneralError
	}

	return ExitSuccess
}

func removeHostSandbox() (int, error) {
	path := filepath.Join(os.TempDir(), "argus")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	if err := os.RemoveAll(path); err != nil {
		return 0, err
	}

	return 1, nil
}

func removeRootfsSandboxes(rootfsPath string) (int, error) {
	matches, err := filepath.Glob(filepath.Join(rootfsPath, "sandbox", "run-*"))
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, err
		}
		if !info.IsDir() {
			continue
		}

		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

func countStaleCgroups() (int, error) {
	matches, err := filepath.Glob(filepath.Join("/sys/fs/cgroup", "argus-*"))
	if err != nil {
		return 0, err
	}

	return len(matches), nil
}
