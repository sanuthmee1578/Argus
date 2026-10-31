package rootfs

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func Validate(rootfsPath string) []string {
	missing := []string{}

	requiredPaths := map[string]string{
		"/usr/bin/python3":                      "Python interpreter",
		"/dev/null":                             "Required device file for process execution",
		"/lib64/ld-linux-x86-64.so.2":           "Dynamic loader",
		"/usr/local/bin/argus-exec":             "Seccomp execution helper",
		"/lib/x86_64-linux-gnu/libseccomp.so.2": "Seccomp runtime library",
	}

	for path, description := range requiredPaths {
		fullPath := filepath.Join(rootfsPath, path[1:])
		if _, err := os.Stat(fullPath); err != nil {
			missing = append(missing, path+" unavailable: "+description+" ("+err.Error()+")")
		}
	}

	pythonStdlibMatches, err := filepath.Glob(filepath.Join(rootfsPath, "usr/lib/python3.*"))
	if err != nil || len(pythonStdlibMatches) == 0 {
		missing = append(missing, "/usr/lib/python3.x missing: Python standard library")
	}

	return missing

}

func createDevNull(rootfsPath string) error {
	devNullPath := filepath.Join(rootfsPath, "dev/null")

	if err := os.Remove(devNullPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	mode := uint32(syscall.S_IFCHR | 0666)
	device := int((1 << 8) | 3)

	if err := syscall.Mknod(devNullPath, mode, device); err != nil {
		return err
	}

	return os.Chmod(devNullPath, 0666)
}

func resolveHelperPath() (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate Argus executable: %w", err)
	}

	return resolveHelperFromDir(filepath.Dir(executablePath))
}

func resolveHelperFromDir(executableDir string) (string, error) {
	candidates := []string{
		filepath.Join(executableDir, "argus-exec"),
		filepath.Join(executableDir, "bin", "argus-exec"),
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf(
		"argus-exec helper not found beside Argus executable or in its bin directory",
	)
}

func Setup(rootfsPath string) error {
	// Create necessary directories
	dirs := []string{
		"usr/bin",
		"usr/local/bin",
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

	helperSrc, err := resolveHelperPath()
	if err != nil {
		return err
	}

	helperDst := filepath.Join(rootfsPath, "usr/local/bin/argus-exec")

	err = copyFile(helperSrc, helperDst)
	if err != nil {
		return err
	}

	err = copyLibraries(
		rootfsPath,
		"/usr/bin/python3",
		helperSrc,
	)

	if err != nil {
		return err
	}

	pythonStdlibSrc, err := findPythonStdlib()
	if err != nil {
		return err
	}

	pythonVersionDir := filepath.Base(pythonStdlibSrc)
	pythonStdlibDst := filepath.Join(rootfsPath, "usr/lib", pythonVersionDir)

	err = copyDir(pythonStdlibSrc, pythonStdlibDst)
	if err != nil {
		return err
	}

	err = createDevNull(rootfsPath)
	if err != nil {
		return err
	}

	return nil
}

func copyFile(src string, dst string) error {
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.OpenFile(
		dst,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		sourceInfo.Mode(),
	)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return os.Chmod(dst, sourceInfo.Mode())
}

func copyLibraries(rootfsPath string, binaryPaths ...string) error {
	seen := make(map[string]bool)

	for _, binaryPath := range binaryPaths {
		libraries, err := discoverLibraries(binaryPath)
		if err != nil {
			return err
		}

		for _, libPath := range libraries {
			if seen[libPath] {
				continue
			}
			seen[libPath] = true

			dst := filepath.Join(rootfsPath, strings.TrimPrefix(libPath, "/"))

			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}

			if err := copyFile(libPath, dst); err != nil {
				return err
			}
		}
	}

	return nil
}

func copyDir(src string, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dst, 0755)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = copyDir(srcPath, dstPath)
			if err != nil {
				return err
			}
		} else {
			err = copyFile(srcPath, dstPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func findPythonStdlib() (string, error) {
	matches, err := filepath.Glob("/usr/lib/python3.*")
	if err != nil {
		return "", err
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no Python standard library found under /usr/lib")
	}

	return matches[0], nil
}

func discoverLibraries(binaryPath string) ([]string, error) {
	output, err := exec.Command("ldd", binaryPath).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect dependencies for %s: %w", binaryPath, err)
	}

	var libraries []string

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Example:
		// libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x...)
		if strings.Contains(line, "=>") {
			parts := strings.Fields(line)
			if len(parts) >= 3 && filepath.IsAbs(parts[2]) {
				libraries = append(libraries, parts[2])
			}
			continue
		}

		// Example:
		// /lib64/ld-linux-x86-64.so.2 (0x...)
		parts := strings.Fields(line)
		if len(parts) >= 1 && filepath.IsAbs(parts[0]) {
			libraries = append(libraries, parts[0])
		}
	}

	return libraries, nil
}
