package rootfs

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDiscoverLibrariesParsesLddOutput(t *testing.T) {
	lddOutput := `
		linux-vdso.so.1 (0x00007ffe317d4000)
		libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fdbfba00000)
		libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdbfb800000)
		/lib64/ld-linux-x86-64.so.2 (0x00007fdbfbd00000)
		statically linked
	`
	withFakeLDD(t, lddOutput, 0)

	got, err := discoverLibraries("/usr/bin/python3")
	if err != nil {
		t.Fatalf("discoverLibraries() unexpected error: %v", err)
	}

	want := []string{
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discoverLibraries() = %#v, want %#v", got, want)
	}
}

func TestDiscoverLibrariesReturnsCommandError(t *testing.T) {
	withFakeLDD(t, "ldd failed\n", 1)

	_, err := discoverLibraries("/missing/binary")
	if err == nil {
		t.Fatal("discoverLibraries() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "failed to inspect dependencies for /missing/binary") {
		t.Fatalf("discoverLibraries() error = %q, want binary path context", err.Error())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		populate  func(t *testing.T, root string)
		wantEmpty bool
		wantParts []string
	}{
		{
			name: "complete rootfs",
			populate: func(t *testing.T, root string) {
				t.Helper()
				createFile(t, root, "usr/bin/python3")
				createFile(t, root, "dev/null")
				createFile(t, root, "lib64/ld-linux-x86-64.so.2")
				createFile(t, root, "usr/local/bin/argus-exec")
				createFile(t, root, "lib/x86_64-linux-gnu/libseccomp.so.2")
				if err := os.MkdirAll(filepath.Join(root, "usr/lib/python3.11"), 0755); err != nil {
					t.Fatalf("create python stdlib directory: %v", err)
				}
			},
			wantEmpty: true,
		},
		{
			name: "missing required files",
			wantParts: []string{
				"/usr/bin/python3 unavailable",
				"/dev/null unavailable",
				"/lib64/ld-linux-x86-64.so.2 unavailable",
				"/usr/local/bin/argus-exec unavailable",
				"/lib/x86_64-linux-gnu/libseccomp.so.2 unavailable",
				"/usr/lib/python3.x missing",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.populate != nil {
				tt.populate(t, root)
			}

			got := Validate(root)
			if tt.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("Validate() = %#v, want no missing paths", got)
				}
				return
			}

			sort.Strings(got)
			for _, want := range tt.wantParts {
				if !containsPart(got, want) {
					t.Fatalf("Validate() = %#v, want entry containing %q", got, want)
				}
			}
		})
	}
}

func withFakeLDD(t *testing.T, output string, exitCode int) {
	t.Helper()

	binDir := t.TempDir()
	script := "#!/bin/sh\ncat <<'EOF'\n" + output + "\nEOF\nexit " + string(rune('0'+exitCode)) + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "ldd"), []byte(script), 0755); err != nil {
		t.Fatalf("write fake ldd: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func createFile(t *testing.T, root string, name string) {
	t.Helper()

	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create parent directory for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

func containsPart(values []string, part string) bool {
	for _, value := range values {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}
