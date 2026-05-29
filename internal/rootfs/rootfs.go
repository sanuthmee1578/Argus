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
		"/usr/lib/python3.12":         "Python standard library",
		"/lib64/ld-linux-x86-64.so.2": "Dynamic loader",
	}

	for path, description := range requiredPaths {
		fullPath := filepath.Join(rootfsPath, path[1:])
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			missing = append(missing, path+" missing: "+description)
		}
	}

	return missing

}
