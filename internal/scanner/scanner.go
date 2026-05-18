package scanner

import (
	"os"
	"strings"
)

func Scan(patterns []string, script string) []string {
	data, err := os.ReadFile(script)
	if err != nil {
		return []string{"Error reading script: " + err.Error()}
	}
	content := string(data)

	var warnings []string

	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			warnings = append(warnings, pattern)
		}
	}
	return warnings
}
