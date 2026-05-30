package rootfs

import (
	"io"
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

func Setup(rootfsPath string) error {
	// Create necessary directories
	dirs := []string{
		"usr/bin",
		"dev",
		"lib/x86_64-linux-gnu",
		"lib64",
		"usr/lib",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(rootfsPath, dir), 0755); err != nil {
			return err
		}
	}

	pythonDst := filepath.Join(rootfsPath, "usr/bin/python3")
	err := copyFile("/usr/bin/python3", pythonDst)
	if err != nil {
		return err
	}

	return nil
}

func copyFile(src string, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}
	return nil
}
