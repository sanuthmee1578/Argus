package report

import (
	"argus/internal/behavior"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteCreatesTextAndJSONReports(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "reports")
	startTime := time.Date(2026, 8, 1, 10, 30, 0, 0, time.UTC)
	endTime := startTime.Add(1500 * time.Millisecond)

	paths, err := Write(directory, Report{
		RunID:       "12345",
		Script:      "script.py",
		Status:      "SUCCESS",
		Output:      "hello\n",
		DurationMS:  1500,
		PID:         42,
		StartTime:   startTime,
		EndTime:     endTime,
		Warnings:    []string{"os.system"},
		Analysis:    []behavior.Analysis{{Pattern: "os.system", Risk: "HIGH", Intent: "Shell execution", Explanation: "Script may execute arbitrary system commands."}},
		SandboxPath: "/tmp/argus/run-123",
		MonitorResults: map[string]string{
			"MemoryExceeded": "false",
			"PeakVmRSS":      "1024 kB",
		},
	})
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	if paths.Text != filepath.Join(directory, "12345.log") {
		t.Fatalf("text path = %q", paths.Text)
	}
	if paths.JSON != filepath.Join(directory, "12345.json") {
		t.Fatalf("JSON path = %q", paths.JSON)
	}

	textData, err := os.ReadFile(paths.Text)
	if err != nil {
		t.Fatalf("read text report: %v", err)
	}
	text := string(textData)
	for _, want := range []string{
		"ARGUS EXECUTION REPORT",
		"Run ID: 12345",
		"Script: script.py",
		"Status: SUCCESS",
		"Duration: 1500ms",
		"Process ID: 42",
		"Warnings:\n- os.system",
		"Analysis:\n- Pattern: os.system",
		"Monitor Results:\n- MemoryExceeded: false\n- PeakVmRSS: 1024 kB",
		"Output:\nhello",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text report missing %q:\n%s", want, text)
		}
	}

	jsonData, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}
	if decoded.RunID != "12345" || decoded.Status != "SUCCESS" || decoded.Output != "hello\n" {
		t.Fatalf("decoded report = %#v", decoded)
	}
}

func TestWriteRejectsExistingReports(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "duplicate.log")
	if err := os.WriteFile(existing, []byte("existing"), 0600); err != nil {
		t.Fatalf("create existing report: %v", err)
	}

	_, err := Write(directory, Report{RunID: "duplicate"})
	if err == nil {
		t.Fatal("Write() error = nil, want existing report error")
	}
}

func TestWriteUsesRestrictivePermissions(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	paths, err := Write(t.TempDir(), Report{RunID: "perms"})
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	for _, path := range []string{paths.Text, paths.JSON} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat report: %v", err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("%s permissions = %v, want 0600", path, got)
		}
	}
}

func TestWriteRequiresRunID(t *testing.T) {
	if _, err := Write(t.TempDir(), Report{}); err == nil {
		t.Fatal("Write() accepted empty run ID")
	}
}

func TestRestoreInvokingUserOwnershipSkipsWithoutSudo(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	path := filepath.Join(t.TempDir(), "report.log")
	if err := os.WriteFile(path, []byte("report"), 0600); err != nil {
		t.Fatalf("create report: %v", err)
	}

	if err := restoreInvokingUserOwnership(path); err != nil {
		t.Fatalf("restoreInvokingUserOwnership() unexpected error: %v", err)
	}
}

func TestRestoreInvokingUserOwnershipRejectsIncompleteSudoEnv(t *testing.T) {
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "")

	err := restoreInvokingUserOwnership("report.log")
	if err == nil {
		t.Fatal("restoreInvokingUserOwnership() error = nil, want incomplete sudo env error")
	}
	if !strings.Contains(err.Error(), "incomplete sudo ownership information") {
		t.Fatalf("restoreInvokingUserOwnership() error = %q", err)
	}
}

func TestRestoreInvokingUserOwnershipRejectsInvalidSudoEnv(t *testing.T) {
	tests := []struct {
		name    string
		uidText string
		gidText string
		want    string
	}{
		{name: "invalid uid", uidText: "not-a-uid", gidText: "1000", want: "parse SUDO_UID"},
		{name: "invalid gid", uidText: "1000", gidText: "not-a-gid", want: "parse SUDO_GID"},
		{name: "negative uid", uidText: "-1", gidText: "1000", want: "invalid invoking-user ownership"},
		{name: "negative gid", uidText: "1000", gidText: "-1", want: "invalid invoking-user ownership"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tt.uidText)
			t.Setenv("SUDO_GID", tt.gidText)

			err := restoreInvokingUserOwnership("report.log")
			if err == nil {
				t.Fatal("restoreInvokingUserOwnership() error = nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("restoreInvokingUserOwnership() error = %q, want %q", err, tt.want)
			}
		})
	}
}
