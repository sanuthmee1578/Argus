package cli

import (
	"argus/internal/report"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func RunInspect(
	out io.Writer,
	errOut io.Writer,
	reportDirectory string,
	runID string,
) int {
	if !validRunID(runID) {
		fmt.Fprintf(errOut, "invalid run ID: %s\n", runID)
		return ExitGeneralError
	}

	path := filepath.Join(reportDirectory, runID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "read report %q: %v\n", path, err)
		return ExitGeneralError
	}

	var executionReport report.Report
	if err := json.Unmarshal(data, &executionReport); err != nil {
		fmt.Fprintf(errOut, "parse report %q: %v\n", path, err)
		return ExitGeneralError
	}

	printSection(out, "Argus execution report")
	printField(out, "Run ID", executionReport.RunID)
	printField(out, "Target", executionReport.Script)
	printField(out, "Status", executionReport.Status)
	printField(out, "Execution time", time.Duration(executionReport.DurationMS)*time.Millisecond)
	if !executionReport.StartTime.IsZero() {
		printField(out, "Started", executionReport.StartTime.Format(time.RFC3339))
	}
	if !executionReport.EndTime.IsZero() {
		printField(out, "Completed", executionReport.EndTime.Format(time.RFC3339))
	}
	printField(out, "Warnings", len(executionReport.Warnings))
	if peakMemory := formatPeakMemory(executionReport.MonitorResults["PeakVmRSS"]); peakMemory != "" {
		printField(out, "Peak memory", peakMemory)
	}
	if executionReport.PID != 0 {
		printField(out, "Process ID", executionReport.PID)
	}
	if executionReport.SandboxPath != "" {
		printField(out, "Sandbox", executionReport.SandboxPath)
	}

	if len(executionReport.Analysis) > 0 {
		fmt.Fprintln(out)
		printSection(out, "Behavior analysis")
		printBehaviorAnalysis(out, executionReport.Analysis)
	}

	if strings.TrimSpace(executionReport.Output) != "" {
		fmt.Fprintln(out)
		printProgramOutput(out, executionReport.Output)
	}

	return ExitSuccess
}

func validRunID(runID string) bool {
	if runID == "" || runID == "." || runID == ".." {
		return false
	}

	return filepath.Base(runID) == runID
}
