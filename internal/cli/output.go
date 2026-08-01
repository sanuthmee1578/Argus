package cli

import (
	"argus/internal/behavior"
	"fmt"
	"io"
	"strings"
)

func printSection(w io.Writer, title string) {
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("─", 48))
}

func printField(w io.Writer, label string, value any) {
	fmt.Fprintf(w, "%-18s %v\n", label, value)
}

func printStep(w io.Writer, passed bool, message string) {
	status := "PASS"
	if !passed {
		status = "FAIL"
	}

	fmt.Fprintf(w, "[%s] %s\n", status, message)
}

func printBehaviorAnalysis(
	w io.Writer,
	analysis []behavior.Analysis,
) {
	for _, finding := range analysis {
		fmt.Fprintf(
			w,
			"  %-7s %s\n",
			finding.Risk,
			finding.Intent,
		)
		fmt.Fprintf(w, "          Pattern: %s\n", finding.Pattern)
		fmt.Fprintf(w, "          %s\n\n", finding.Explanation)
	}
}
