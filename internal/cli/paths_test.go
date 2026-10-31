package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePolicyFromDir(t *testing.T) {
	tests := []struct {
		name      string
		insideBin bool
		wantError bool
	}{
		{"release layout", false, false},
		{"bin installation layout", true, false},
		{"missing policy", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			executableDir := root

			if tt.insideBin {
				executableDir = filepath.Join(root, "bin")
				if err := os.MkdirAll(executableDir, 0755); err != nil {
					t.Fatal(err)
				}
			}

			expected := filepath.Join(root, "config", "policy.json")

			if !tt.wantError {
				if err := os.MkdirAll(filepath.Dir(expected), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(expected, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			}

			got, err := resolvePolicyFromDir(executableDir)

			if tt.wantError {
				if err == nil {
					t.Fatal("expected an error for missing policy")
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
