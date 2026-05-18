package monitor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ReadStatus(pid int) map[string]string {

	results := map[string]string{}

	pidString := strconv.Itoa(pid)

	path := "/proc/" + pidString + "/status"

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading process status:", err)
		return results
	}

	content := string(data)

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		found := strings.Contains(line, "State:")

		if found {
			results["State"] = line
		}

		found = strings.Contains(line, "VmRSS:")

		if found {
			results["VmRSS"] = line
		}

		found = strings.Contains(line, "Threads:")

		if found {
			results["Threads"] = line
		}
	}

	return results

}
