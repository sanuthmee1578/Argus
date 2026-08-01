package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScanSafeScript(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeCLITestPolicy(t, dir, false, false)
	scriptPath := writeCLITestFile(t, dir, "safe.py", "print('hello')\n")
	var output bytes.Buffer

	exitCode := RunScan(&output, policyPath, scriptPath)

	if exitCode != ExitSuccess {
		t.Fatalf("RunScan() exit = %d, want %d:\n%s", exitCode, ExitSuccess, output.String())
	}
	if !strings.Contains(output.String(), "Result: SAFE") {
		t.Fatalf("scan output missing safe result:\n%s", output.String())
	}
}

func TestRunScanSuspiciousScript(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeCLITestPolicy(t, dir, true, false)
	scriptPath := writeCLITestFile(t, dir, "suspicious.py", "import os\nos.system('id')\n")
	var output bytes.Buffer

	exitCode := RunScan(&output, policyPath, scriptPath)

	if exitCode != ExitBlocked {
		t.Fatalf("RunScan() exit = %d, want %d:\n%s", exitCode, ExitBlocked, output.String())
	}

	text := output.String()
	for _, want := range []string{
		"Result: SUSPICIOUS",
		"Behavior analysis",
		"HIGH    Shell execution",
		"Pattern: os.system",
		"Script may execute arbitrary system commands.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("scan output missing %q:\n%s", want, text)
		}
	}

	if strings.Contains(text, "{os.system HIGH") {
		t.Fatalf("scan output contains raw struct formatting:\n%s", text)
	}
}

func TestRunScanMissingScript(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeCLITestPolicy(t, dir, false, false)
	var output bytes.Buffer

	exitCode := RunScan(&output, policyPath, filepath.Join(dir, "missing.py"))

	if exitCode != ExitGeneralError {
		t.Fatalf("RunScan() exit = %d, want %d", exitCode, ExitGeneralError)
	}
	if !strings.Contains(output.String(), "[FAIL] Script unavailable") {
		t.Fatalf("scan output missing script error:\n%s", output.String())
	}
}

func TestRunScanInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeCLITestFile(t, dir, "safe.py", "print('hello')\n")
	policyPath := writeCLITestFile(t, dir, "policy.json", "{")
	var output bytes.Buffer

	exitCode := RunScan(&output, policyPath, scriptPath)

	if exitCode != ExitGeneralError {
		t.Fatalf("RunScan() exit = %d, want %d", exitCode, ExitGeneralError)
	}
	if !strings.Contains(output.String(), "[FAIL] Policy load failed") {
		t.Fatalf("scan output missing policy error:\n%s", output.String())
	}
}

func writeCLITestPolicy(t *testing.T, dir string, strict bool, chroot bool) string {
	t.Helper()

	policyPath := filepath.Join(dir, "policy.json")
	strictValue := "false"
	if strict {
		strictValue = "true"
	}
	chrootValue := "false"
	if chroot {
		chrootValue = "true"
	}

	data := `{
		"timeout": 5,
		"strict_mode": ` + strictValue + `,
		"blocked_patterns": ["os.system", "subprocess.Popen", "rm -rf"],
		"memory_limit_mb": 128,
		"pids_limit": 32,
		"cpu_quota": 50000,
		"cpu_period": 100000,
		"keep_sandbox": true,
		"rootfs_path": "` + filepath.ToSlash(filepath.Join(dir, "rootfs")) + `",
		"enable_chroot": ` + chrootValue + `,
		"enable_seccomp": false,
		"seccomp_profile": "none"
	}`

	if err := os.WriteFile(policyPath, []byte(data), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	return policyPath
}

func writeCLITestFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}
