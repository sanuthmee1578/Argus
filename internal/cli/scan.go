package cli

import (
	"argus/internal/behavior"
	"argus/internal/policy"
	"argus/internal/scanner"
	"fmt"
	"io"
	"os"
)

func RunScan(
	w io.Writer,
	policyPath string,
	scriptPath string,
) int {
	PrintBanner(w)

	fmt.Fprintln(w, "Static security scan")
	fmt.Fprintln(w, "────────────────────────────────────────")
	fmt.Fprintf(w, "Target: %s\n\n", scriptPath)

	if _, err := os.Stat(scriptPath); err != nil {
		fmt.Fprintf(w, "[FAIL] Script unavailable: %v\n", err)
		return ExitGeneralError
	}

	loadedPolicy, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(w, "[FAIL] Policy load failed: %v\n", err)
		return ExitGeneralError
	}

	warnings := scanner.Scan(
		loadedPolicy.BlockedPatterns,
		scriptPath,
	)

	analysis := behavior.Analyze(warnings)

	fmt.Fprintln(w, "[PASS] Policy loaded")
	fmt.Fprintln(w, "[PASS] Script scanned")
	fmt.Fprintln(w)

	if len(warnings) == 0 {
		fmt.Fprintln(w, "Result: SAFE")
		fmt.Fprintln(w, "No suspicious patterns detected.")
		return ExitSuccess
	}

	fmt.Fprintln(w, "Result: SUSPICIOUS")
	fmt.Fprintf(w, "Warnings: %d\n", len(warnings))
	fmt.Fprintln(w)

	for index, warning := range warnings {
		fmt.Fprintf(
			w,
			"  %d. %s\n",
			index+1,
			warning,
		)
	}

	if len(analysis) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Behavior analysis")
		fmt.Fprintln(w)
		printBehaviorAnalysis(w, analysis)
	}

	if loadedPolicy.StrictMode {
		fmt.Fprintln(w)
		fmt.Fprintln(
			w,
			"Policy decision: execution would be blocked in strict mode.",
		)
	}

	return ExitBlocked
}
