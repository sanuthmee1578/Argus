package rootfs

import (
	"os"
	"path/filepath"
)

func Validate(rootfsPath string) []string {
	missing := []string{}

	requiredPaths := map[string]string{
		"/usr/bin/python3":            "Python interpreter",
		"/dev/null":                   "Required device file for process execution",
		"/lib64/ld-linux-x86-64.so.2": "Dynamic loader",
	}

	for path, description := range requiredPaths {
		fullPath := filepath.Join(rootfsPath, path[1:])
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			missing = append(missing, path+" missing: "+description)
		}
	}

	pythonStdlibMatches, err := filepath.Glob(filepath.Join(rootfsPath, "usr/lib/python3.*"))
	if err != nil || len(pythonStdlibMatches) == 0 {
		missing = append(missing, "/usr/lib/python3.x missing: Python standard library")
	}

	return missing

}
