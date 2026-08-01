package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/behavior"
	"argus/internal/report"
)

func TestRunInspectDisplaysReport(t *testing.T) {
	dir := t.TempDir()
	reportDir := filepath.Join(dir, "reports")
	start := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	if _, err := report.Write(reportDir, report.Report{
		RunID:      "inspect-run",
		Script:     "script.py",
		Status:     "MEMORY_LIMIT_EXCEEDED",
		Output:     "partial output\n",
		DurationMS: 322,
		StartTime:  start,
		EndTime:    start.Add(322 * time.Millisecond),
		Warnings:   []string{"os.system"},
		Analysis: []behavior.Analysis{
			{
				Pattern:     "os.system",
				Risk:        "HIGH",
				Intent:      "Shell execution",
				Explanation: "Script may execute arbitrary system commands.",
			},
		},
		MonitorResults: map[string]string{
			"PeakVmRSS": "12288 kB",
		},
	}); err != nil {
		t.Fatalf("write report: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := RunInspect(&stdout, &stderr, reportDir, "inspect-run")

	if exitCode != ExitSuccess {
		t.Fatalf("RunInspect() exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", exitCode, ExitSuccess, stdout.String(), stderr.String())
	}

	text := stdout.String()
	for _, want := range []string{
		"Argus execution report",
		"Run ID             inspect-run",
		"Target             script.py",
		"Status             MEMORY_LIMIT_EXCEEDED",
		"Execution time     322ms",
		"Warnings           1",
		"Peak memory        12 MB",
		"Behavior analysis",
		"Pattern: os.system",
		"Output",
		"partial output",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("inspect output missing %q:\n%s", want, text)
		}
	}
}

func TestRunInspectRejectsInvalidRunID(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := RunInspect(&stdout, &stderr, t.TempDir(), "../escape")

	if exitCode != ExitGeneralError {
		t.Fatalf("RunInspect() exit = %d, want %d", exitCode, ExitGeneralError)
	}
	if !strings.Contains(stderr.String(), "invalid run ID") {
		t.Fatalf("inspect stderr missing invalid run ID error:\n%s", stderr.String())
	}
}

func TestRunInspectMissingReport(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := RunInspect(&stdout, &stderr, t.TempDir(), "missing")

	if exitCode != ExitGeneralError {
		t.Fatalf("RunInspect() exit = %d, want %d", exitCode, ExitGeneralError)
	}
	if !strings.Contains(stderr.String(), "read report") {
		t.Fatalf("inspect stderr missing read report error:\n%s", stderr.String())
	}
}
