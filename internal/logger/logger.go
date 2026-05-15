package logger

import (
	"os"
	"time"
	"strconv"
)

func Write(script string, status string, output string, warnings []string, duration time.Duration, pid int) error {
	report := "ARGUS EXECUTION REPORT\n"
	report += "Script: " + script + "\n"
	report += "Status: " + status + "\n"
	report += "Output:\n" + output + "\n"
	report +=  "Execution Time: " + duration.String() + "\n"
	report += "Process ID: " + strconv.Itoa(pid) + "\n"
	report += "Warnings:\n"
	
	if len(warnings) > 0 {
	for _, warning := range warnings {
		report += "- " + warning + "\n"
	}
	}else{
		report += "None\n"
	}

	err := os.WriteFile("./logs/report.log", []byte(report), 0644)
		if err != nil {
			return err
		}

	return nil

	}
	