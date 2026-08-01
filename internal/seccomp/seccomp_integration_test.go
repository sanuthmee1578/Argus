//go:build linux && seccomp_integration

package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

const seccompIntegrationChildEnv = "ARGUS_SECCOMP_INTEGRATION_CHILD"

func TestNoNetworkProfileBlocksSocketSyscall(t *testing.T) {
	if mode := os.Getenv(seccompIntegrationChildEnv); mode != "" {
		runSeccompIntegrationChild(mode)
		return
	}

	requirePrivilegedSeccompIntegration(t)

	output, err := runSeccompIntegrationSubprocess(t, "no-network-socket", "TestNoNetworkProfileBlocksSocketSyscall")
	if err != nil {
		t.Fatalf("no-network socket child failed: %v\n%s", err, output)
	}
}

func TestStrictProfileKillsBlockedSyscall(t *testing.T) {
	if mode := os.Getenv(seccompIntegrationChildEnv); mode != "" {
		runSeccompIntegrationChild(mode)
		return
	}

	requirePrivilegedSeccompIntegration(t)

	output, err := runSeccompIntegrationSubprocess(t, "strict-reboot", "TestStrictProfileKillsBlockedSyscall")
	if err == nil {
		t.Fatalf("strict reboot child exited successfully, want seccomp kill\n%s", output)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("strict reboot child failed with non-exit error: %v\n%s", err, output)
	}

	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("strict reboot child has unexpected wait status: %v\n%s", exitErr.Sys(), output)
	}
	if !status.Signaled() || status.Signal() != syscall.SIGSYS {
		t.Fatalf("strict reboot child status = %v, want SIGSYS\n%s", status, output)
	}
}

func requirePrivilegedSeccompIntegration(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("privileged seccomp integration tests require root; run with sudo go test -tags seccomp_integration ./internal/seccomp")
	}
}

func runSeccompIntegrationSubprocess(t *testing.T, mode string, testName string) (string, error) {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	cmd := exec.Command(executable, "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), seccompIntegrationChildEnv+"="+mode)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runSeccompIntegrationChild(mode string) {
	switch mode {
	case "no-network-socket":
		if err := ApplyProfile("no-network"); err != nil {
			exitChildf("ApplyProfile(no-network): %v", err)
		}

		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != syscall.EPERM {
			if err == nil {
				_ = syscall.Close(fd)
			}
			exitChildf("socket errno = %v, want %v", err, syscall.EPERM)
		}
		os.Exit(0)
	case "strict-reboot":
		if err := ApplyProfile("strict"); err != nil {
			exitChildf("ApplyProfile(strict): %v", err)
		}

		_, _, _ = syscall.Syscall(syscall.SYS_REBOOT, 0, 0, 0)
		exitChildf("reboot syscall returned; want seccomp kill")
	default:
		exitChildf("unknown child mode %q", mode)
	}
}

func exitChildf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
