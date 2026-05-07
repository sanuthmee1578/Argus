package scanner
import (
	"os"
	"strings"
)

func Scan(script string) []string {
	data, err := os.ReadFile(script)
	if err != nil {
		return []string{"Error reading script: " + err.Error()}
	}

	content := string(data)
	patterns := [] string{
		"rm -rf",
		"os.system",
		"subprocess",
		"while True",
	}

	var warnings []string

	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			warnings = append(warnings, pattern)
	}
	}
	return warnings
}




