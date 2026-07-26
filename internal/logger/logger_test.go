package logger

import (
	"argus/internal/behavior"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteCreatesReport(t *testing.T) {
	workDir := t.TempDir()
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	if err := os.Mkdir("reports", 0755); err != nil {
		t.Fatalf("create reports directory: %v", err)
	}

	start := time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)
	end := start.Add(2 * time.Second)
	err = Write(
		"script.py",
		"BLOCKED_BY_POLICY",
		"denied",
		[]string{"os.system"},
		2*time.Second,
		1234,
		start,
		end,
		map[string]string{"memory": "10MB"},
		[]behavior.Analysis{
			{
				Pattern:     "os.system",
				Risk:        "HIGH",
				Intent:      "Shell execution",
				Explanation: "Script may execute arbitrary system commands.",
			},
		},
	)
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(workDir, "reports", "run_*_BLOCKED_BY_POLICY.log"))
	if err != nil {
		t.Fatalf("glob reports: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("created %d report files, want 1", len(matches))
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	report := string(data)
	for _, want := range []string{
		"ARGUS EXECUTION REPORT",
		"Script: script.py",
		"Status: BLOCKED_BY_POLICY",
		"Output:\ndenied",
		"Execution Time: 2s",
		"Process ID: 1234",
		"Start Time: 2026-07-19 10:30:00",
		"End Time: 2026-07-19 10:30:02",
		"Warnings:\n- os.system",
		"Monitor Results:\n- memory: 10MB",
		"Analysis:\n- Pattern: os.system",
		"  Risk: HIGH",
		"  Intent: Shell execution",
		"  Explanation: Script may execute arbitrary system commands.",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestWriteReportsNoWarnings(t *testing.T) {
	workDir := t.TempDir()
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	if err := os.Mkdir("reports", 0755); err != nil {
		t.Fatalf("create reports directory: %v", err)
	}

	err = Write("safe.py", "OK", "done", nil, time.Second, 42, time.Time{}, time.Time{}, nil, nil)
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(workDir, "reports", "run_*_OK.log"))
	if err != nil {
		t.Fatalf("glob reports: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("created %d report files, want 1", len(matches))
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "Warnings:\nNone\n") {
		t.Fatalf("report did not include empty warning marker:\n%s", string(data))
	}
}

func TestWriteReturnsErrorWhenReportsDirectoryMissing(t *testing.T) {
	workDir := t.TempDir()
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	err = Write("safe.py", "OK", "", nil, 0, 0, time.Time{}, time.Time{}, nil, nil)
	if err == nil {
		t.Fatal("Write() error = nil, want an error")
	}
}
