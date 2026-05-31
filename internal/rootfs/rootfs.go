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

	err = copyLibraries(rootfsPath)
	if err != nil {
		return err
	}

	pythonStdlibSrc := "/usr/lib/python3.12"
	pythonStdlibDst := filepath.Join(rootfsPath, "usr/lib/python3.12")

	err = copyDir(pythonStdlibSrc, pythonStdlibDst)
	if err != nil {
		return err
	}

	devNullPath := filepath.Join(rootfsPath, "dev/null")

	err = os.WriteFile(devNullPath, []byte{}, 0666)
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

func copyLibraries(rootfsPath string) error {
	lib := []string{
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/lib/x86_64-linux-gnu/libz.so.1",
		"/lib/x86_64-linux-gnu/libexpat.so.1",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
	}

	for _, libPath := range lib {
		dst := filepath.Join(rootfsPath, libPath[1:])
		err := os.MkdirAll(filepath.Dir(dst), 0755)
		if err != nil {
			return err
		}
		err = copyFile(libPath, dst)
		if err != nil {
			return err
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
