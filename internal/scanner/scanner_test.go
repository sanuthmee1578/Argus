package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScan(t *testing.T) {
	t.Parallel()

	patterns := []string{"import socket", "subprocess", "os.system"}

	tests := []struct {
		name    string
		script  string
		want    []string
		wantLen int
	}{
		{
			name:   "safe script",
			script: "print('hello from argus')\n",
		},
		{
			name:   "import socket",
			script: "import socket\nprint(socket.AF_INET)\n",
			want:   []string{"import socket"},
		},
		{
			name:   "subprocess",
			script: "import subprocess\nsubprocess.Popen(['echo', 'hi'])\n",
			want:   []string{"subprocess"},
		},
		{
			name:   "os.system",
			script: "import os\nos.system('whoami')\n",
			want:   []string{"os.system"},
		},
		{
			name:   "empty script",
			script: "",
		},
		{
			name:   "multiple detections",
			script: "import socket\nimport os\nimport subprocess\nos.system('id')\n",
			want:   []string{"import socket", "subprocess", "os.system"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "script.py")
			if err := os.WriteFile(path, []byte(tt.script), 0644); err != nil {
				t.Fatalf("write script fixture: %v", err)
			}

			got := Scan(patterns, path)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Scan() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestScanMissingScript(t *testing.T) {
	t.Parallel()

	got := Scan([]string{"os.system"}, filepath.Join(t.TempDir(), "missing.py"))
	if len(got) != 1 {
		t.Fatalf("Scan() returned %d warnings, want 1", len(got))
	}
	if got[0] == "" {
		t.Fatal("Scan() returned an empty read-error warning")
	}
}
