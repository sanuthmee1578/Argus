package rootfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveHelperFromDir(t *testing.T) {
	tests := []struct {
		name      string
		insideBin bool
		wantError bool
	}{
		{"release layout", false, false},
		{"repository layout", true, false},
		{"missing helper", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			expected := filepath.Join(root, "argus-exec")

			if tt.insideBin {
				expected = filepath.Join(root, "bin", "argus-exec")
			}

			if !tt.wantError {
				if err := os.MkdirAll(filepath.Dir(expected), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(expected, []byte("test helper"), 0755); err != nil {
					t.Fatal(err)
				}
			}

			got, err := resolveHelperFromDir(root)

			if tt.wantError {
				if err == nil {
					t.Fatal("expected an error for missing helper")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != expected {
				t.Fatalf("got %q, want %q", got, expected)
			}
		})
	}
}
