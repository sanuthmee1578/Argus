package logger

import (
	"os"
	"strconv"
	"time"
)

func Write(script string, status string, output string, warnings []string, duration time.Duration, pid int, startTime time.Time, endTime time.Time, monitorResults map[string]string) error {
	report := "ARGUS EXECUTION REPORT\n"
	report += "Script: " + script + "\n"
	report += "Status: " + status + "\n"
	report += "Output:\n" + output + "\n"
	report += "Execution Time: " + duration.String() + "\n"
	report += "Process ID: " + strconv.Itoa(pid) + "\n"
	report += "Start Time: " + startTime.Format("2006-01-02 15:04:05") + "\n"
	report += "End Time: " + endTime.Format("2006-01-02 15:04:05") + "\n"
	report += "Warnings:\n"

	if len(warnings) > 0 {
		for _, warning := range warnings {
			report += "- " + warning + "\n"
		}
	} else {
		report += "None\n"
	}

	if len(monitorResults) > 0 {
		report += "Monitor Results:\n"
		for key, value := range monitorResults {
			report += "- " + key + ": " + value + "\n"
		}
	}

	timestamp := time.Now().Format("2006-01-02T15-04-05.000")

	filename := "./reports/run_" + timestamp + "_" + status + ".log"

	err := os.WriteFile(filename, []byte(report), 0644)
	if err != nil {
		return err
	}

	return nil

}
