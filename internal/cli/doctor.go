package cli

import (
	"argus/internal/policy"
	"argus/internal/rootfs"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type doctorCheck struct {
	name    string
	passed  bool
	details string
}

func RunDoctor(w io.Writer, policyPath string) int {
	PrintBanner(w)
	fmt.Fprintln(w, "Environment check")
	fmt.Fprintln(w, "────────────────────────────────────────")

	checks := []doctorCheck{
		{
			name:    "Linux operating system",
			passed:  runtime.GOOS == "linux",
			details: runtime.GOOS + "/" + runtime.GOARCH,
		},
	}

	loadedPolicy, err := policy.Load(policyPath)
	if err != nil {
		checks = append(checks, doctorCheck{
			name:    "Policy configuration",
			passed:  false,
			details: err.Error(),
		})

		printDoctorChecks(w, checks)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Argus is not ready.")
		return ExitGeneralError
	}

	checks = append(checks, doctorCheck{
		name:    "Policy configuration",
		passed:  true,
		details: policyPath,
	})

	checks = append(checks, checkPath(
		"cgroup v2",
		"/sys/fs/cgroup/cgroup.controllers",
	))

	rootfsPath := loadedPolicy.RootfsPath

	rootfsInfo, rootfsErr := os.Stat(rootfsPath)
	checks = append(checks, doctorCheck{
		name:   "Rootfs directory",
		passed: rootfsErr == nil && rootfsInfo.IsDir(),
		details: func() string {
			if rootfsErr != nil {
				return rootfsErr.Error()
			}

			if !rootfsInfo.IsDir() {
				return "path exists but is not a directory"
			}

			return rootfsPath
		}(),
	})

	if rootfsErr == nil && rootfsInfo.IsDir() {
		missing := rootfs.Validate(rootfsPath)

		checks = append(checks, doctorCheck{
			name:   "Rootfs validation",
			passed: len(missing) == 0,
			details: func() string {
				if len(missing) == 0 {
					return "required runtime files are available"
				}

				return fmt.Sprintf("%d required item(s) missing", len(missing))
			}(),
		})
	}

	checks = append(checks,
		checkPath(
			"Python runtime",
			filepath.Join(rootfsPath, "usr", "bin", "python3"),
		),
		checkPath(
			"Seccomp execution helper",
			filepath.Join(
				rootfsPath,
				"usr",
				"local",
				"bin",
				"argus-exec",
			),
		),
		checkPath(
			"libseccomp runtime",
			filepath.Join(
				rootfsPath,
				"lib",
				"x86_64-linux-gnu",
				"libseccomp.so.2",
			),
		),
		checkPath(
			"/dev/null device",
			filepath.Join(rootfsPath, "dev", "null"),
		),
	)

	checks = append(checks, doctorCheck{
		name:   "Current privileges",
		passed: os.Geteuid() == 0,
		details: func() string {
			if os.Geteuid() == 0 {
				return "root privileges available"
			}

			return "run execution commands with sudo while chroot is enabled"
		}(),
	})

	printDoctorChecks(w, checks)

	failures := 0
	for _, check := range checks {
		if !check.passed {
			failures++
		}
	}

	fmt.Fprintln(w)

	if failures == 0 {
		fmt.Fprintln(w, "Argus is ready to execute workloads.")
		return ExitSuccess
	}

	fmt.Fprintf(
		w,
		"Argus is not fully ready: %d check(s) failed.\n",
		failures,
	)

	return ExitGeneralError
}

func checkPath(name string, path string) doctorCheck {
	info, err := os.Stat(path)
	if err != nil {
		return doctorCheck{
			name:    name,
			passed:  false,
			details: err.Error(),
		}
	}

	details := path
	if info.IsDir() {
		details += " (directory)"
	}

	return doctorCheck{
		name:    name,
		passed:  true,
		details: details,
	}
}

func printDoctorChecks(w io.Writer, checks []doctorCheck) {
	for _, check := range checks {
		status := "PASS"
		if !check.passed {
			status = "FAIL"
		}

		fmt.Fprintf(
			w,
			"[%s] %-27s %s\n",
			status,
			check.name,
			check.details,
		)
	}
}
