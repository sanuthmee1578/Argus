package cli

import (
	"argus/internal/behavior"
	"argus/internal/policy"
	"argus/internal/report"
	"argus/internal/rootfs"
	"argus/internal/runner"
	"argus/internal/scanner"
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type ExecuteFunc func(
	script string,
	timeout time.Duration,
	memoryLimitMB int,
	keepSandbox bool,
	rootfsPath string,
	enableChroot bool,
	enableSeccomp bool,
	seccompProfile string,
	pidsLimit int,
	cpuQuota int,
	cpuPeriod int,
) runner.Result

type RunDependencies struct {
	Execute ExecuteFunc
}

func RunScript(
	in io.Reader,
	out io.Writer,
	errOut io.Writer,
	policyPath string,
	scriptPath string,
) int {
	return RunScriptWithDependencies(
		in,
		out,
		errOut,
		policyPath,
		scriptPath,
		RunDependencies{
			Execute: runner.Run,
		},
	)
}

func RunScriptWithDependencies(
	in io.Reader,
	out io.Writer,
	errOut io.Writer,
	policyPath string,
	scriptPath string,
	dependencies RunDependencies,
) int {
	PrintBanner(out)
	startTime := time.Now()
	execute := dependencies.Execute
	if execute == nil {
		execute = runner.Run
	}

	if _, err := os.Stat(scriptPath); err != nil {
		printSection(out, "Secure execution")
		printField(out, "Target", scriptPath)
		fmt.Fprintln(out)
		fmt.Fprintf(errOut, "script unavailable: %v\n", err)
		return ExitGeneralError
	}

	loadedPolicy, err := policy.Load(policyPath)
	if err != nil {
		printSection(out, "Secure execution")
		printField(out, "Target", scriptPath)
		printField(out, "Policy", policyPath)
		fmt.Fprintln(out)
		fmt.Fprintf(errOut, "policy load failed: %v\n", err)
		return ExitGeneralError
	}

	timeout := time.Duration(loadedPolicy.Timeout) * time.Second
	printRunConfiguration(out, policyPath, scriptPath, loadedPolicy, timeout)

	warnings := scanner.Scan(
		loadedPolicy.BlockedPatterns,
		scriptPath,
	)
	analysis := behavior.Analyze(warnings)

	printStep(out, true, "Policy loaded")
	printStep(out, true, "Static pattern scan completed")

	if len(warnings) > 0 {
		fmt.Fprintf(out, "[WARN] %d suspicious pattern(s) detected\n", len(warnings))
		fmt.Fprintln(out)
		printSection(out, "Behavior analysis")
		printBehaviorAnalysis(out, analysis)

		if loadedPolicy.StrictMode {
			fmt.Fprintln(out)
			printField(out, "Result", "BLOCKED_BY_POLICY")
			printField(out, "Reason", "Suspicious patterns rejected by strict mode")

			paths, err := report.Write(
				"reports",
				blockedReport(
					newRunID(),
					scriptPath,
					"BLOCKED_BY_POLICY",
					"Script blocked due to strict mode.",
					startTime,
					warnings,
					analysis,
				),
			)
			if err != nil {
				fmt.Fprintf(errOut, "write report: %v\n", err)
				return ExitGeneralError
			}

			fmt.Fprintln(out)
			printReportPaths(out, paths)
			return ExitBlocked
		}

		fmt.Fprint(out, "Continue with isolated execution? [y/N]: ")
		if !confirmed(in) {
			fmt.Fprintln(out)
			printField(out, "Result", "BLOCKED_BY_USER")
			printField(out, "Reason", "Execution cancelled by user")

			paths, err := report.Write(
				"reports",
				blockedReport(
					newRunID(),
					scriptPath,
					"BLOCKED_BY_USER",
					"Execution aborted by the user.",
					startTime,
					warnings,
					analysis,
				),
			)
			if err != nil {
				fmt.Fprintf(errOut, "write report: %v\n", err)
				return ExitGeneralError
			}

			fmt.Fprintln(out)
			printReportPaths(out, paths)
			return ExitBlocked
		}
		fmt.Fprintln(out)
	}

	if loadedPolicy.EnableChroot && os.Geteuid() != 0 {
		printStep(out, false, "Execution environment ready")
		fmt.Fprintf(errOut, "chroot mode requires root privileges; run with sudo or disable enable_chroot\n")
		return ExitGeneralError
	}

	if loadedPolicy.EnableChroot {
		missing := rootfs.Validate(loadedPolicy.RootfsPath)
		if len(missing) > 0 {
			printStep(out, false, "Rootfs validated")
			for _, issue := range missing {
				fmt.Fprintf(errOut, "rootfs validation failed: %s\n", issue)
			}
			return ExitGeneralError
		}
	}

	printStep(out, true, "Rootfs validated")
	printStep(out, true, "Execution environment ready")
	fmt.Fprintln(out)

	result := execute(
		scriptPath,
		timeout,
		loadedPolicy.MemoryLimitMB,
		loadedPolicy.KeepSandbox,
		loadedPolicy.RootfsPath,
		loadedPolicy.EnableChroot,
		loadedPolicy.EnableSeccomp,
		loadedPolicy.SeccompProfile,
		loadedPolicy.PidsLimit,
		loadedPolicy.CPUQuota,
		loadedPolicy.CPUPeriod,
	)

	paths, err := report.Write(
		"reports",
		reportFromResult(
			result,
			scriptPath,
			warnings,
			analysis,
		),
	)
	if err != nil {
		fmt.Fprintf(errOut, "write report: %v\n", err)
		return ExitGeneralError
	}

	printExecutionResult(out, result)
	printProgramOutput(out, result.Output)
	fmt.Fprintln(out)
	printReportPaths(out, paths)

	if result.Status == "ERROR" && result.ErrorMessage != "" {
		fmt.Fprintf(errOut, "%s\n", result.ErrorMessage)
	}

	return exitCodeForStatus(result.Status)
}

func blockedReport(
	runID string,
	scriptPath string,
	status string,
	errorMessage string,
	startTime time.Time,
	warnings []string,
	analysis []behavior.Analysis,
) report.Report {
	endTime := time.Now()
	warnings = normalizeWarnings(warnings)
	analysis = normalizeAnalysis(analysis)

	return report.Report{
		RunID:          runID,
		Script:         scriptPath,
		Status:         status,
		ErrorMessage:   errorMessage,
		DurationMS:     endTime.Sub(startTime).Milliseconds(),
		StartTime:      startTime,
		EndTime:        endTime,
		Warnings:       warnings,
		Analysis:       analysis,
		MonitorResults: map[string]string{},
	}
}

func reportFromResult(
	result runner.Result,
	scriptPath string,
	warnings []string,
	analysis []behavior.Analysis,
) report.Report {
	warnings = normalizeWarnings(warnings)
	analysis = normalizeAnalysis(analysis)

	return report.Report{
		RunID:          result.RunID,
		Script:         scriptPath,
		Status:         result.Status,
		Output:         result.Output,
		ErrorMessage:   result.ErrorMessage,
		DurationMS:     result.Duration.Milliseconds(),
		PID:            result.PID,
		StartTime:      result.StartTime,
		EndTime:        result.EndTime,
		Warnings:       warnings,
		Analysis:       analysis,
		MonitorResults: result.MonitorResults,
		SandboxPath:    result.SandboxPath,
	}
}

func normalizeWarnings(warnings []string) []string {
	if warnings == nil {
		return []string{}
	}
	return warnings
}

func normalizeAnalysis(analysis []behavior.Analysis) []behavior.Analysis {
	if analysis == nil {
		return []behavior.Analysis{}
	}
	return analysis
}

func printReportPaths(w io.Writer, paths report.Paths) {
	printSection(w, "Reports")
	printField(w, "Text", paths.Text)
	printField(w, "JSON", paths.JSON)
}

func newRunID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func printRunConfiguration(
	w io.Writer,
	policyPath string,
	scriptPath string,
	loadedPolicy policy.Policy,
	timeout time.Duration,
) {
	printSection(w, "Secure execution")
	printField(w, "Target", scriptPath)
	printField(w, "Policy", policyPath)
	printField(w, "Strict mode", enabledLabel(loadedPolicy.StrictMode))
	printField(w, "Chroot", enabledLabel(loadedPolicy.EnableChroot))
	printField(w, "Namespaces", namespaceLabel(loadedPolicy.EnableChroot))
	printField(w, "Seccomp", seccompLabel(loadedPolicy.EnableSeccomp, loadedPolicy.SeccompProfile))
	printField(w, "Memory limit", fmt.Sprintf("%d MB", loadedPolicy.MemoryLimitMB))
	printField(w, "PID limit", loadedPolicy.PidsLimit)
	printField(w, "CPU quota", fmt.Sprintf("%d / %d", loadedPolicy.CPUQuota, loadedPolicy.CPUPeriod))
	printField(w, "Timeout", timeout)
	printField(w, "Keep sandbox", loadedPolicy.KeepSandbox)
	fmt.Fprintln(w)
}

func printExecutionResult(w io.Writer, result runner.Result) {
	printSection(w, "Execution result")
	printField(w, "Run ID", result.RunID)
	printField(w, "Status", result.Status)
	if reason := resultReason(result); reason != "" {
		printField(w, "Reason", reason)
	}
	if result.PID != 0 {
		printField(w, "Process ID", result.PID)
	}
	if result.Duration != 0 {
		printField(w, "Execution time", result.Duration)
	}
	if peakMemory := formatPeakMemory(result.MonitorResults["PeakVmRSS"]); peakMemory != "" {
		printField(w, "Peak memory", peakMemory)
	}
	if memoryExceeded, ok := result.MonitorResults["MemoryExceeded"]; ok {
		printField(w, "Memory exceeded", memoryExceeded)
	}
	if result.SandboxKept && result.SandboxPath != "" {
		printField(w, "Sandbox retained", result.SandboxPath)
	}
	fmt.Fprintln(w)
}

func printProgramOutput(w io.Writer, output string) {
	printSection(w, "Program output")
	if strings.TrimSpace(output) == "" {
		fmt.Fprintln(w, "No program output.")
		return
	}

	fmt.Fprint(w, output)
	if !strings.HasSuffix(output, "\n") {
		fmt.Fprintln(w)
	}
}

func confirmed(in io.Reader) bool {
	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false
	}

	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func namespaceLabel(enableChroot bool) string {
	if enableChroot {
		return "mount + PID + network"
	}
	return "disabled"
}

func seccompLabel(enableSeccomp bool, profile string) string {
	if !enableSeccomp {
		return "disabled"
	}
	if profile == "" {
		return "enabled"
	}
	return profile
}

func formatPeakMemory(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}

	kib, err := strconv.Atoi(fields[0])
	if err != nil {
		return value
	}

	if kib == 0 {
		return "not sampled"
	}
	if kib < 1024 {
		return "< 1 MB"
	}

	mb := kib / 1024
	if kib%1024 != 0 {
		mb++
	}

	return fmt.Sprintf("%d MB", mb)
}

func resultReason(result runner.Result) string {
	switch result.Status {
	case "TIMEOUT":
		if result.ErrorMessage != "" {
			return result.ErrorMessage
		}
		return "Execution exceeded the configured timeout"
	case "MEMORY_LIMIT_EXCEEDED":
		return "Execution exceeded the configured memory limit"
	case "SECURITY_VIOLATION":
		return result.ErrorMessage
	case "ERROR":
		return result.ErrorMessage
	default:
		return ""
	}
}

func exitCodeForStatus(status string) int {
	switch status {
	case "SUCCESS":
		return ExitSuccess
	case "TIMEOUT":
		return ExitTimeout
	case "MEMORY_LIMIT_EXCEEDED":
		return ExitMemoryExceeded
	case "SECURITY_VIOLATION":
		return ExitSecurityViolation
	case "ERROR":
		return ExitExecutionFailed
	default:
		return ExitGeneralError
	}
}
