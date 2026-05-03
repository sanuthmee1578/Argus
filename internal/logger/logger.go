package logger

import (
	"os"
)

func Write(script string, status string, output string) error {
	log := "\nScript: " + script +
		"\nStatus: " + status +
		"\nOutput:\n" + output

	err := os.WriteFile("./logs/latest.log", []byte(log), 0644)
	if err != nil {
		return err
	}

	return nil
}