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
	startTime := time.Now()
	execute := dependencies.Execute
	if execute == nil {
		execute = runner.Run
	}

	if _, err := os.Stat(scriptPath); err != nil {
		printRunTitle(out)
		printField(out, "Target", scriptPath)
		fmt.Fprintln(out)
		fmt.Fprintf(errOut, "script unavailable: %v\n", err)
		return ExitGeneralError
	}

	loadedPolicy, err := policy.Load(policyPath)
	if err != nil {
		printRunTitle(out)
		printField(out, "Target", scriptPath)
		printField(out, "Policy", policyPath)
		fmt.Fprintln(out)
		fmt.Fprintf(errOut, "policy load failed: %v\n", err)
		return ExitGeneralError
	}

	timeout := time.Duration(loadedPolicy.Timeout) * time.Second
	printRunHeader(out, scriptPath, policyPath)

	warnings := scanner.Scan(
		loadedPolicy.BlockedPatterns,
		scriptPath,
	)
	analysis := behavior.Analyze(warnings)

	if len(warnings) > 0 {
		printChecks(out, checkState{"Policy", true}, checkState{"Static Scan", true})
		fmt.Fprintln(out)
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
		reason := "chroot mode requires root privileges; run with sudo or disable enable_chroot"
		printChecks(
			out,
			checkState{"Policy", true},
			checkState{"Static Scan", true},
			checkState{"Rootfs", true},
			checkState{"Environment", false},
		)
		printField(out, "Reason", reason)
		fmt.Fprintln(out)
		return ExitGeneralError
	}

	if loadedPolicy.EnableChroot {
		missing := rootfs.Validate(loadedPolicy.RootfsPath)
		if len(missing) > 0 {
			reason := "rootfs validation failed"
			printChecks(
				out,
				checkState{"Policy", true},
				checkState{"Static Scan", true},
				checkState{"Rootfs", false},
				checkState{"Environment", false},
			)
			printField(out, "Reason", reason)
			fmt.Fprintln(out)
			for _, issue := range missing {
				fmt.Fprintf(errOut, "%s: %s\n", reason, issue)
			}
			return ExitGeneralError
		}
	}

	printChecks(
		out,
		checkState{"Policy", true},
		checkState{"Static Scan", true},
		checkState{"Rootfs", true},
		checkState{"Environment", true},
	)
	fmt.Fprintln(out)
	printRunConfiguration(out, loadedPolicy, timeout)

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

	fmt.Fprintln(out)
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
	printField(w, "log", paths.Text)
	printField(w, "json", paths.JSON)
}

func newRunID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

type checkState struct {
	name   string
	passed bool
}

func printRunTitle(w io.Writer) {
	printCenteredRunLogo(w)
	fmt.Fprintln(w, strings.Repeat("─", 72))
}

func printCenteredRunLogo(w io.Writer) {
	logoLines := []string{
		"    ___",
		"   /   |  _________ ___  _______",
		"  / /| | / ___/ __ `/ / / / ___/",
		" / ___ |/ /  / /_/ / /_/ (__  )",
		"/_/  |_/_/   \\__, /\\__,_/____/",
		"            /____/",
		"",
		"Argus Secure Execution Runtime",
	}

	for _, line := range logoLines {
		fmt.Fprintln(w, centerText(line, 72))
	}
}

func centerText(text string, width int) string {
	if text == "" {
		return ""
	}
	if len(text) >= width {
		return text
	}
	leftPadding := (width - len(text)) / 2
	return strings.Repeat(" ", leftPadding) + text
}

func printRunHeader(w io.Writer, scriptPath string, policyPath string) {
	printRunTitle(w)
	printTwoColumnFields(
		w,
		[2]string{"Target", scriptPath},
		[2]string{"Policy", policyPath},
	)
	fmt.Fprintln(w)
}

func printChecks(w io.Writer, checks ...checkState) {
	fmt.Fprint(w, "Checks: ")
	for index, check := range checks {
		if index > 0 {
			fmt.Fprint(w, "  ")
		}

		marker := "✓"
		if !check.passed {
			marker = "✗"
		}
		fmt.Fprintf(w, "%s %s", marker, check.name)
	}
	fmt.Fprintln(w)
}

func printRunConfiguration(w io.Writer, loadedPolicy policy.Policy, timeout time.Duration) {
	printSection(w, "Configuration")
	printTwoColumnFields(
		w,
		[2]string{"Strict", enabledLabel(loadedPolicy.StrictMode)},
		[2]string{"Chroot", enabledLabel(loadedPolicy.EnableChroot)},
	)
	printTwoColumnFields(
		w,
		[2]string{"Namespaces", namespaceLabel(loadedPolicy.EnableChroot)},
		[2]string{"Seccomp", seccompLabel(loadedPolicy.EnableSeccomp, loadedPolicy.SeccompProfile)},
	)
	printTwoColumnFields(
		w,
		[2]string{"Memory", fmt.Sprintf("%d MB", loadedPolicy.MemoryLimitMB)},
		[2]string{"PID limit", strconv.Itoa(loadedPolicy.PidsLimit)},
	)
	printTwoColumnFields(
		w,
		[2]string{"CPU quota", fmt.Sprintf("%d/%d", loadedPolicy.CPUQuota, loadedPolicy.CPUPeriod)},
		[2]string{"Timeout", formatDuration(timeout)},
	)
	printTwoColumnFields(
		w,
		[2]string{"Sandbox", sandboxLabel(loadedPolicy.KeepSandbox)},
		[2]string{"Rootfs", loadedPolicy.RootfsPath},
	)
}

func printExecutionResult(w io.Writer, result runner.Result) {
	printSection(w, "Result")
	fmt.Fprintf(w, "%s %s\n", statusMarker(result.Status), result.Status)
	if reason := resultReason(result); reason != "" {
		printField(w, "Reason", reason)
	}
	fmt.Fprintln(w)

	printTwoColumnFields(
		w,
		[2]string{"Run ID", result.RunID},
		[2]string{"PID", pidLabel(result.PID)},
	)
	printTwoColumnFields(
		w,
		[2]string{"Time", formatDuration(result.Duration)},
		[2]string{"Peak RSS", formatPeakMemory(result.MonitorResults["PeakVmRSS"])},
	)
	printTwoColumnFields(
		w,
		[2]string{"Memory hit", mapValueOr(result.MonitorResults, "MemoryExceeded", "unknown")},
		[2]string{"Sandbox", resultSandboxLabel(result)},
	)
	fmt.Fprintln(w)
}

func printTwoColumnFields(w io.Writer, left [2]string, right [2]string) {
	fmt.Fprintf(
		w,
		"%-12s %-22s  %-12s %s\n",
		left[0],
		left[1],
		right[0],
		right[1],
	)
}

func printProgramOutput(w io.Writer, output string) {
	printSection(w, "Output")
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
		return "mount | pid | network"
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

func sandboxLabel(keepSandbox bool) string {
	if keepSandbox {
		return "retained"
	}
	return "temporary"
}

func resultSandboxLabel(result runner.Result) string {
	if result.SandboxKept && result.SandboxPath != "" {
		return "retained"
	}
	if result.SandboxPath != "" {
		return "temporary"
	}
	return "unknown"
}

func pidLabel(pid int) string {
	if pid == 0 {
		return "unknown"
	}
	return strconv.Itoa(pid)
}

func statusMarker(status string) string {
	switch status {
	case "SUCCESS":
		return "✓"
	case "TIMEOUT", "MEMORY_LIMIT_EXCEEDED", "SECURITY_VIOLATION", "ERROR":
		return "✗"
	default:
		return "!"
	}
}

func formatDuration(duration time.Duration) string {
	if duration == 0 {
		return "unknown"
	}
	if duration < time.Second {
		return fmt.Sprintf("%d ms", duration.Milliseconds())
	}
	return duration.String()
}

func mapValueOr(values map[string]string, key string, fallback string) string {
	if value, ok := values[key]; ok && value != "" {
		return value
	}
	return fallback
}

func formatPeakMemory(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "unknown"
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
