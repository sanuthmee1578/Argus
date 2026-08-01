package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/runner"
)

func TestRunScriptMapsExecutionStatuses(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		wantExit int
	}{
		{name: "success", status: "SUCCESS", wantExit: ExitSuccess},
		{name: "timeout", status: "TIMEOUT", wantExit: ExitTimeout},
		{name: "memory", status: "MEMORY_LIMIT_EXCEEDED", wantExit: ExitMemoryExceeded},
		{name: "security violation", status: "SECURITY_VIOLATION", wantExit: ExitSecurityViolation},
		{name: "error", status: "ERROR", wantExit: ExitExecutionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			restore := chdirCLITest(t, dir)
			defer restore()

			policyPath := writeCLITestPolicy(t, dir, false, false)
			scriptPath := writeCLITestFile(t, dir, "safe.py", "print('hello')\n")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			called := false

			exitCode := RunScriptWithDependencies(
				strings.NewReader(""),
				&stdout,
				&stderr,
				policyPath,
				scriptPath,
				RunDependencies{
					Execute: func(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) runner.Result {
						called = true
						return fakeRunnerResult(tt.status)
					},
				},
			)

			if !called {
				t.Fatal("fake execute was not called")
			}
			if exitCode != tt.wantExit {
				t.Fatalf("RunScriptWithDependencies() exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", exitCode, tt.wantExit, stdout.String(), stderr.String())
			}

			text := stdout.String()
			for _, want := range []string{
				"Secure execution",
				"[PASS] Policy loaded",
				"[PASS] Static pattern scan completed",
				"Execution result",
				"Reports",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("run output missing %q:\n%s", want, text)
				}
			}

			if _, err := os.Stat(filepath.Join(dir, "reports", tt.status+".json")); err != nil {
				t.Fatalf("expected JSON report for %s: %v", tt.status, err)
			}
		})
	}
}

func TestRunScriptStrictModeBlocksWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	restore := chdirCLITest(t, dir)
	defer restore()

	policyPath := writeCLITestPolicy(t, dir, true, false)
	scriptPath := writeCLITestFile(t, dir, "suspicious.py", "import os\nos.system('id')\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := RunScriptWithDependencies(
		strings.NewReader(""),
		&stdout,
		&stderr,
		policyPath,
		scriptPath,
		RunDependencies{
			Execute: func(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) runner.Result {
				called = true
				return fakeRunnerResult("SUCCESS")
			},
		},
	)

	if called {
		t.Fatal("execute was called for strict-mode suspicious script")
	}
	if exitCode != ExitBlocked {
		t.Fatalf("RunScriptWithDependencies() exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", exitCode, ExitBlocked, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "BLOCKED_BY_POLICY") {
		t.Fatalf("run output missing strict block result:\n%s", stdout.String())
	}
}

func TestRunScriptNonStrictCancelBlocksWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	restore := chdirCLITest(t, dir)
	defer restore()

	policyPath := writeCLITestPolicy(t, dir, false, false)
	scriptPath := writeCLITestFile(t, dir, "suspicious.py", "import os\nos.system('id')\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	exitCode := RunScriptWithDependencies(
		strings.NewReader("no\n"),
		&stdout,
		&stderr,
		policyPath,
		scriptPath,
		RunDependencies{
			Execute: func(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) runner.Result {
				called = true
				return fakeRunnerResult("SUCCESS")
			},
		},
	)

	if called {
		t.Fatal("execute was called after non-strict prompt cancellation")
	}
	if exitCode != ExitBlocked {
		t.Fatalf("RunScriptWithDependencies() exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", exitCode, ExitBlocked, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "BLOCKED_BY_USER") {
		t.Fatalf("run output missing user block result:\n%s", stdout.String())
	}
}

func TestRunScriptTimeoutPrintsReasonWithoutTrailingStderr(t *testing.T) {
	dir := t.TempDir()
	restore := chdirCLITest(t, dir)
	defer restore()

	policyPath := writeCLITestPolicy(t, dir, false, false)
	scriptPath := writeCLITestFile(t, dir, "timeout.py", "import time\ntime.sleep(20)\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := RunScriptWithDependencies(
		strings.NewReader(""),
		&stdout,
		&stderr,
		policyPath,
		scriptPath,
		RunDependencies{
			Execute: func(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) runner.Result {
				return fakeRunnerResult("TIMEOUT")
			},
		},
	)

	if exitCode != ExitTimeout {
		t.Fatalf("RunScriptWithDependencies() exit = %d, want %d", exitCode, ExitTimeout)
	}
	if stderr.String() != "" {
		t.Fatalf("timeout should not print trailing stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Reason") ||
		!strings.Contains(stdout.String(), "Execution exceeded the 15s limit") {
		t.Fatalf("timeout output missing reason field:\n%s", stdout.String())
	}
}

func TestRunScriptWritesEmptyArraysForSafeReport(t *testing.T) {
	dir := t.TempDir()
	restore := chdirCLITest(t, dir)
	defer restore()

	policyPath := writeCLITestPolicy(t, dir, false, false)
	scriptPath := writeCLITestFile(t, dir, "safe.py", "print('hello')\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := RunScriptWithDependencies(
		strings.NewReader(""),
		&stdout,
		&stderr,
		policyPath,
		scriptPath,
		RunDependencies{
			Execute: func(script string, timeout time.Duration, memoryLimitMB int, keepSandbox bool, rootfsPath string, enableChroot bool, enableSeccomp bool, seccompProfile string, pidsLimit int, cpuQuota int, cpuPeriod int) runner.Result {
				return fakeRunnerResult("SUCCESS")
			},
		},
	)

	if exitCode != ExitSuccess {
		t.Fatalf("RunScriptWithDependencies() exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", exitCode, ExitSuccess, stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "reports", "SUCCESS.json"))
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}

	var decoded struct {
		Warnings []string `json:"warnings"`
		Analysis []struct {
			Pattern string `json:"pattern"`
		} `json:"analysis"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}
	if decoded.Warnings == nil {
		t.Fatalf("warnings decoded as nil, JSON:\n%s", string(data))
	}
	if decoded.Analysis == nil {
		t.Fatalf("analysis decoded as nil, JSON:\n%s", string(data))
	}
	if len(decoded.Warnings) != 0 || len(decoded.Analysis) != 0 {
		t.Fatalf("decoded warnings/analysis = %#v / %#v, want empty arrays", decoded.Warnings, decoded.Analysis)
	}
}

func TestFormatPeakMemory(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "", want: ""},
		{value: "0 kB", want: "not sampled"},
		{value: "512 kB", want: "< 1 MB"},
		{value: "1024 kB", want: "1 MB"},
		{value: "12288 kB", want: "12 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := formatPeakMemory(tt.value)
			if got != tt.want {
				t.Fatalf("formatPeakMemory(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func fakeRunnerResult(status string) runner.Result {
	start := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	return runner.Result{
		RunID:        status,
		Status:       status,
		Output:       "program output\n",
		ErrorMessage: fakeErrorMessage(status),
		Duration:     52 * time.Millisecond,
		PID:          48891,
		StartTime:    start,
		EndTime:      start.Add(52 * time.Millisecond),
		MonitorResults: map[string]string{
			"PeakVmRSS":      "12288 kB",
			"MemoryExceeded": "false",
		},
		SandboxPath: "/tmp/argus-root/sandbox/run-test",
		SandboxKept: true,
	}
}

func fakeErrorMessage(status string) string {
	if status == "ERROR" {
		return "execute script: exit status 1"
	}
	if status == "TIMEOUT" {
		return "Execution exceeded the 15s limit"
	}
	if status == "SECURITY_VIOLATION" {
		return "Network syscall blocked by seccomp"
	}
	return ""
}

func chdirCLITest(t *testing.T, dir string) func() {
	t.Helper()

	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}

	return func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}
}
