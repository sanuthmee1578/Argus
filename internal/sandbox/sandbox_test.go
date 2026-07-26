package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareSandbox(t *testing.T) {
	tests := []struct {
		name         string
		enableChroot bool
	}{
		{
			name:         "host sandbox",
			enableChroot: false,
		},
		{
			name:         "chroot sandbox",
			enableChroot: true,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			rootfsPath := t.TempDir()
			scriptPath := writeScript(
				t,
				t.TempDir(),
				"script.py",
				"print('hello')\n",
			)

			prepared, err := PrepareSandbox(
				scriptPath,
				tt.enableChroot,
				rootfsPath,
			)
			if err != nil {
				t.Fatalf("PrepareSandbox() unexpected error: %v", err)
			}

			t.Cleanup(func() {
				_ = os.RemoveAll(prepared.HostPath)
			})

			if prepared.HostPath == "" {
				t.Fatal("PrepareSandbox() HostPath is empty")
			}

			if prepared.RuntimePath == "" {
				t.Fatal("PrepareSandbox() RuntimePath is empty")
			}

			if prepared.ScriptName != "script.py" {
				t.Fatalf(
					"PrepareSandbox() ScriptName = %q, want %q",
					prepared.ScriptName,
					"script.py",
				)
			}

			if !strings.Contains(
				filepath.Base(prepared.HostPath),
				"run-",
			) {
				t.Fatalf(
					"PrepareSandbox() HostPath = %q, want run directory",
					prepared.HostPath,
				)
			}

			if tt.enableChroot {
				wantPrefix := filepath.Join(rootfsPath, "sandbox")

				if !pathIsWithin(wantPrefix, prepared.HostPath) {
					t.Fatalf(
						"HostPath = %q, want inside %q",
						prepared.HostPath,
						wantPrefix,
					)
				}

				wantRuntimePrefix :=
					string(filepath.Separator) +
						"sandbox" +
						string(filepath.Separator) +
						"run-"

				if !strings.HasPrefix(
					prepared.RuntimePath,
					wantRuntimePrefix,
				) {
					t.Fatalf(
						"RuntimePath = %q, want chroot runtime path beginning with %q",
						prepared.RuntimePath,
						wantRuntimePrefix,
					)
				}
			} else if prepared.RuntimePath != prepared.HostPath {
				t.Fatalf(
					"RuntimePath = %q, want HostPath %q",
					prepared.RuntimePath,
					prepared.HostPath,
				)
			}

			info, err := os.Stat(prepared.HostPath)
			if err != nil {
				t.Fatalf("stat sandbox directory: %v", err)
			}

			if !info.IsDir() {
				t.Fatalf(
					"sandbox path %q is not a directory",
					prepared.HostPath,
				)
			}

			copiedPath := filepath.Join(
				prepared.HostPath,
				prepared.ScriptName,
			)

			data, err := os.ReadFile(copiedPath)
			if err != nil {
				t.Fatalf("read copied script: %v", err)
			}

			if string(data) != "print('hello')\n" {
				t.Fatalf(
					"copied script content = %q, want exact source contents",
					string(data),
				)
			}

			copiedInfo, err := os.Stat(copiedPath)
			if err != nil {
				t.Fatalf("stat copied script: %v", err)
			}

			if got := copiedInfo.Mode().Perm(); got != 0444 {
				t.Fatalf(
					"copied script permissions = %o, want 0444",
					got,
				)
			}
		})
	}
}

func TestPrepareSandboxUsesUniqueRunDirectories(t *testing.T) {
	rootfsPath := t.TempDir()
	scriptPath := writeScript(
		t,
		t.TempDir(),
		"script.py",
		"print('unique')\n",
	)

	seen := make(map[string]bool)

	for i := 0; i < 10; i++ {
		prepared, err := PrepareSandbox(
			scriptPath,
			false,
			rootfsPath,
		)
		if err != nil {
			t.Fatalf(
				"PrepareSandbox() call %d unexpected error: %v",
				i,
				err,
			)
		}

		t.Cleanup(func() {
			_ = os.RemoveAll(prepared.HostPath)
		})

		if seen[prepared.HostPath] {
			t.Fatalf(
				"PrepareSandbox() reused sandbox directory %q",
				prepared.HostPath,
			)
		}

		seen[prepared.HostPath] = true
	}
}

func TestCopyScriptCopiesExactContents(t *testing.T) {
	srcDir := t.TempDir()
	sandboxDir := t.TempDir()

	content := "print('copy me')\n"
	src := writeScript(
		t,
		srcDir,
		"source.py",
		content,
	)

	err := CopyScript(
		src,
		sandboxDir,
		"copied.py",
	)
	if err != nil {
		t.Fatalf("CopyScript() unexpected error: %v", err)
	}

	dst := filepath.Join(sandboxDir, "copied.py")

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read copied script: %v", err)
	}

	if string(got) != content {
		t.Fatalf(
			"copied script content = %q, want %q",
			string(got),
			content,
		)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat copied script: %v", err)
	}

	if gotPerm := info.Mode().Perm(); gotPerm != 0600 {
		t.Fatalf(
			"copied script permissions = %o, want 0600",
			gotPerm,
		)
	}
}

func TestCopyScriptRejectsExistingDestination(t *testing.T) {
	sandboxDir := t.TempDir()

	src := writeScript(
		t,
		t.TempDir(),
		"source.py",
		"print('source')\n",
	)

	existingPath := writeScript(
		t,
		sandboxDir,
		"copied.py",
		"do not overwrite\n",
	)

	err := CopyScript(
		src,
		sandboxDir,
		"copied.py",
	)
	if err == nil {
		t.Fatal("CopyScript() error = nil, want existing-file error")
	}

	data, readErr := os.ReadFile(existingPath)
	if readErr != nil {
		t.Fatalf("read existing file: %v", readErr)
	}

	if string(data) != "do not overwrite\n" {
		t.Fatalf(
			"existing destination was modified: %q",
			string(data),
		)
	}
}

func TestCopyScriptMissingSourceReturnsError(t *testing.T) {
	sandboxDir := t.TempDir()
	missingSource := filepath.Join(
		t.TempDir(),
		"missing.py",
	)

	err := CopyScript(
		missingSource,
		sandboxDir,
		"copied.py",
	)
	if err == nil {
		t.Fatal("CopyScript() error = nil, want an error")
	}
}

func TestCopyScriptMissingSandboxDirectoryReturnsError(t *testing.T) {
	src := writeScript(
		t,
		t.TempDir(),
		"source.py",
		"print('hello')\n",
	)

	missingSandboxDir := filepath.Join(
		t.TempDir(),
		"missing",
	)

	err := CopyScript(
		src,
		missingSandboxDir,
		"copied.py",
	)
	if err == nil {
		t.Fatal("CopyScript() error = nil, want an error")
	}
}

func TestCopyScriptRejectsUnsafeDestinationNames(t *testing.T) {
	src := writeScript(
		t,
		t.TempDir(),
		"source.py",
		"print('escape')\n",
	)

	tests := []struct {
		name            string
		destinationName string
	}{
		{
			name:            "parent traversal",
			destinationName: "../outside.py",
		},
		{
			name:            "multiple parent traversal",
			destinationName: "../../outside.py",
		},
		{
			name:            "absolute path",
			destinationName: "/tmp/outside.py",
		},
		{
			name:            "nested path",
			destinationName: "nested/script.py",
		},
		{
			name:            "current directory",
			destinationName: ".",
		},
		{
			name:            "parent directory",
			destinationName: "..",
		},
		{
			name:            "empty name",
			destinationName: "",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			sandboxDir := t.TempDir()

			err := CopyScript(
				src,
				sandboxDir,
				tt.destinationName,
			)
			if err == nil {
				t.Fatalf(
					"CopyScript() error = nil for destination %q, want rejection",
					tt.destinationName,
				)
			}
		})
	}
}

func writeScript(
	t *testing.T,
	dir string,
	name string,
	content string,
) string {
	t.Helper()

	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}

	return path
}

func pathIsWithin(basePath, candidatePath string) bool {
	baseAbs, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}

	candidateAbs, err := filepath.Abs(candidatePath)
	if err != nil {
		return false
	}

	relativePath, err := filepath.Rel(baseAbs, candidateAbs)
	if err != nil {
		return false
	}

	return relativePath != ".." &&
		!strings.HasPrefix(
			relativePath,
			".."+string(filepath.Separator),
		)
}
