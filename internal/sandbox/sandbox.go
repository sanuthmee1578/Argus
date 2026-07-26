package sandbox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type PreparedSandbox struct {
	HostPath    string
	RuntimePath string
	ScriptName  string
}

func PrepareSandbox(
	scriptPath string,
	enableChroot bool,
	rootfsPath string,
) (PreparedSandbox, error) {
	var parentDir string

	if enableChroot {
		parentDir = filepath.Join(rootfsPath, "sandbox")
	} else {
		parentDir = filepath.Join(os.TempDir(), "argus")
	}

	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return PreparedSandbox{}, fmt.Errorf(
			"create sandbox parent directory: %w",
			err,
		)
	}

	// MkdirTemp creates the directory atomically with a unique random suffix.
	sandboxPath, err := os.MkdirTemp(parentDir, "run-")
	if err != nil {
		return PreparedSandbox{}, fmt.Errorf(
			"create unique sandbox directory: %w",
			err,
		)
	}

	// Remove partially prepared sandboxes when setup fails.
	setupComplete := false
	defer func() {
		if !setupComplete {
			_ = os.RemoveAll(sandboxPath)
		}
	}()

	scriptName := filepath.Base(scriptPath)
	if scriptName == "." || scriptName == string(filepath.Separator) {
		return PreparedSandbox{}, fmt.Errorf("invalid script path %q", scriptPath)
	}

	if err := CopyScript(scriptPath, sandboxPath, scriptName); err != nil {
		return PreparedSandbox{}, fmt.Errorf("copy script into sandbox: %w", err)
	}

	sandboxScriptPath := filepath.Join(sandboxPath, scriptName)

	if err := os.Chmod(sandboxScriptPath, 0444); err != nil {
		return PreparedSandbox{}, fmt.Errorf(
			"make sandbox script read-only: %w",
			err,
		)
	}

	runDirectoryName := filepath.Base(sandboxPath)

	var runtimePath string
	if enableChroot {
		runtimePath = filepath.Join("/sandbox", runDirectoryName)
	} else {
		runtimePath = sandboxPath
	}

	setupComplete = true

	return PreparedSandbox{
		HostPath:    sandboxPath,
		RuntimePath: runtimePath,
		ScriptName:  scriptName,
	}, nil
}

func CopyScript(src, sandboxDir, destinationName string) error {
	if err := validateDestinationName(destinationName); err != nil {
		return err
	}

	destinationPath := filepath.Join(sandboxDir, destinationName)

	if err := ensurePathWithinDirectory(sandboxDir, destinationPath); err != nil {
		return err
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source script: %w", err)
	}
	defer sourceFile.Close()

	destinationFile, err := os.OpenFile(
		destinationPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create destination script: %w", err)
	}

	copyErr := func() error {
		defer destinationFile.Close()

		if _, err := io.Copy(destinationFile, sourceFile); err != nil {
			return fmt.Errorf("copy script contents: %w", err)
		}

		if err := destinationFile.Sync(); err != nil {
			return fmt.Errorf("sync destination script: %w", err)
		}

		return nil
	}()

	if copyErr != nil {
		_ = os.Remove(destinationPath)
		return copyErr
	}

	return nil
}

func validateDestinationName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid destination name %q", name)
	}

	if filepath.IsAbs(name) {
		return fmt.Errorf("absolute destination paths are not allowed: %q", name)
	}

	if filepath.Base(name) != name {
		return fmt.Errorf("destination must be a filename, not a path: %q", name)
	}

	if strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("destination contains a path separator: %q", name)
	}

	return nil
}

func ensurePathWithinDirectory(baseDir, destinationPath string) error {
	cleanBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve sandbox directory: %w", err)
	}

	cleanDestination, err := filepath.Abs(destinationPath)
	if err != nil {
		return fmt.Errorf("resolve destination path: %w", err)
	}

	relativePath, err := filepath.Rel(cleanBase, cleanDestination)
	if err != nil {
		return fmt.Errorf("compare sandbox paths: %w", err)
	}

	if relativePath == ".." ||
		strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return fmt.Errorf(
			"destination %q escapes sandbox directory %q",
			destinationPath,
			baseDir,
		)
	}

	return nil
}
