package policy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	validPolicy := `{
		"timeout": 15,
		"strict_mode": true,
		"blocked_patterns": ["os.system", "socket.connect"],
		"memory_limit_mb": 100,
		"pids_limit": 20,
		"cpu_quota": 50000,
		"cpu_period": 100000,
		"keep_sandbox": false,
		"rootfs_path": "/tmp/argus-root",
		"enable_chroot": true,
		"enable_seccomp": true,
		"seccomp_profile": "no-network"
	}`

	tests := []struct {
		name        string
		content     string
		missingFile bool
		want        Policy
		wantErr     string
	}{
		{
			name:    "valid policy",
			content: validPolicy,
			want: Policy{
				Timeout:         15,
				StrictMode:      true,
				BlockedPatterns: []string{"os.system", "socket.connect"},
				MemoryLimitMB:   100,
				PidsLimit:       20,
				CPUQuota:        50000,
				CPUPeriod:       100000,
				KeepSandbox:     false,
				RootfsPath:      "/tmp/argus-root",
				EnableChroot:    true,
				EnableSeccomp:   true,
				SeccompProfile:  "no-network",
			},
		},
		{
			name:        "missing file",
			missingFile: true,
			wantErr:     "error reading policy file",
		},
		{
			name:    "invalid json",
			content: `{"timeout":`,
			wantErr: "error parsing policy file",
		},
		{
			name:    "empty file",
			content: "",
			wantErr: "error parsing policy file",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "policy.json")
			if !tt.missingFile {
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatalf("write policy fixture: %v", err)
				}
			}

			got, err := Load(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Load() error = nil, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
				if tt.missingFile && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Load() error does not wrap os.ErrNotExist: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Load() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
