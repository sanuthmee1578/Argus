package report

import (
	"argus/internal/behavior"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	RunID          string              `json:"run_id"`
	Script         string              `json:"script"`
	Status         string              `json:"status"`
	Output         string              `json:"output,omitempty"`
	ErrorMessage   string              `json:"error_message,omitempty"`
	DurationMS     int64               `json:"duration_ms"`
	PID            int                 `json:"pid,omitempty"`
	StartTime      time.Time           `json:"start_time"`
	EndTime        time.Time           `json:"end_time"`
	Warnings       []string            `json:"warnings"`
	Analysis       []behavior.Analysis `json:"analysis"`
	MonitorResults map[string]string   `json:"monitor_results"`
	SandboxPath    string              `json:"sandbox_path,omitempty"`
}

type Paths struct {
	Text string
	JSON string
}

func Write(directory string, report Report) (Paths, error) {
	if report.RunID == "" {
		return Paths{}, fmt.Errorf("run ID is required")
	}

	if err := os.MkdirAll(directory, 0700); err != nil {
		return Paths{}, fmt.Errorf("create report directory: %w", err)
	}

	paths := Paths{
		Text: filepath.Join(directory, report.RunID+".log"),
		JSON: filepath.Join(directory, report.RunID+".json"),
	}

	if err := ensureDoesNotExist(paths.Text); err != nil {
		return Paths{}, err
	}
	if err := ensureDoesNotExist(paths.JSON); err != nil {
		return Paths{}, err
	}

	if err := writeAtomic(paths.Text, []byte(formatText(report))); err != nil {
		return Paths{}, fmt.Errorf("write text report: %w", err)
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Paths{}, fmt.Errorf("format JSON report: %w", err)
	}
	jsonData = append(jsonData, '\n')

	if err := writeAtomic(paths.JSON, jsonData); err != nil {
		return Paths{}, fmt.Errorf("write JSON report: %w", err)
	}

	if err := restoreInvokingUserOwnership(paths.Text, paths.JSON); err != nil {
		return Paths{}, err
	}

	return paths, nil
}

func restoreInvokingUserOwnership(paths ...string) error {
	uidText := os.Getenv("SUDO_UID")
	gidText := os.Getenv("SUDO_GID")

	// Argus was not started through sudo.
	if uidText == "" && gidText == "" {
		return nil
	}

	if uidText == "" || gidText == "" {
		return fmt.Errorf(
			"incomplete sudo ownership information: SUDO_UID=%q SUDO_GID=%q",
			uidText,
			gidText,
		)
	}

	uid, err := strconv.Atoi(uidText)
	if err != nil {
		return fmt.Errorf("parse SUDO_UID %q: %w", uidText, err)
	}

	gid, err := strconv.Atoi(gidText)
	if err != nil {
		return fmt.Errorf("parse SUDO_GID %q: %w", gidText, err)
	}

	if uid < 0 || gid < 0 {
		return fmt.Errorf(
			"invalid invoking-user ownership: uid=%d gid=%d",
			uid,
			gid,
		)
	}

	for _, path := range paths {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf(
				"restore ownership of report %q to %d:%d: %w",
				path,
				uid,
				gid,
				err,
			)
		}
	}

	return nil
}

func ensureDoesNotExist(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("report already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check report path %s: %w", path, err)
	}

	return nil
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	base := filepath.Base(path)

	tempFile, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}

	tempPath := tempFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set temporary report permissions: %w", err)
	}

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temporary report: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temporary report: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}

	if err := ensureDoesNotExist(path); err != nil {
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename temporary report: %w", err)
	}

	cleanup = false
	return nil
}

func formatText(report Report) string {
	var builder strings.Builder

	builder.WriteString("ARGUS EXECUTION REPORT\n")
	builder.WriteString("Run ID: " + report.RunID + "\n")
	builder.WriteString("Script: " + report.Script + "\n")
	builder.WriteString("Status: " + report.Status + "\n")
	if report.ErrorMessage != "" {
		builder.WriteString("Error: " + report.ErrorMessage + "\n")
	}
	builder.WriteString(fmt.Sprintf("Duration: %dms\n", report.DurationMS))
	if report.PID != 0 {
		builder.WriteString(fmt.Sprintf("Process ID: %d\n", report.PID))
	}
	builder.WriteString("Start Time: " + report.StartTime.Format(time.RFC3339Nano) + "\n")
	builder.WriteString("End Time: " + report.EndTime.Format(time.RFC3339Nano) + "\n")
	if report.SandboxPath != "" {
		builder.WriteString("Sandbox Path: " + report.SandboxPath + "\n")
	}

	builder.WriteString("Warnings:\n")
	if len(report.Warnings) == 0 {
		builder.WriteString("None\n")
	} else {
		for _, warning := range report.Warnings {
			builder.WriteString("- " + warning + "\n")
		}
	}

	if len(report.Analysis) > 0 {
		builder.WriteString("Analysis:\n")
		for _, finding := range report.Analysis {
			builder.WriteString("- Pattern: " + finding.Pattern + "\n")
			builder.WriteString("  Risk: " + finding.Risk + "\n")
			builder.WriteString("  Intent: " + finding.Intent + "\n")
			builder.WriteString("  Explanation: " + finding.Explanation + "\n")
		}
	}

	if len(report.MonitorResults) > 0 {
		builder.WriteString("Monitor Results:\n")
		keys := make([]string, 0, len(report.MonitorResults))
		for key := range report.MonitorResults {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			builder.WriteString("- " + key + ": " + report.MonitorResults[key] + "\n")
		}
	}

	builder.WriteString("Output:\n")
	if report.Output == "" {
		builder.WriteString("None\n")
	} else {
		builder.WriteString(report.Output)
		if !strings.HasSuffix(report.Output, "\n") {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}
