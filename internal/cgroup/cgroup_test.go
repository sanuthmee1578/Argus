package cgroup

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCreateAtCreatesCorrectDirectoryName(t *testing.T) {
	basePath := t.TempDir()

	got, err := CreateAt(basePath, "run-123", 64, 32, 50000, 100000)
	if err != nil {
		t.Fatalf("CreateAt returned error: %v", err)
	}

	want := filepath.Join(basePath, "argus-run-123")
	if got != want {
		t.Fatalf("CreateAt path = %q, want %q", got, want)
	}

	if info, err := os.Stat(want); err != nil {
		t.Fatalf("created cgroup directory: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("created path is not a directory: %s", want)
	}
}

func TestCreateAtWritesMemoryMaxBytes(t *testing.T) {
	basePath := t.TempDir()

	cgroupPath, err := CreateAt(basePath, "memory", 128, 32, 50000, 100000)
	if err != nil {
		t.Fatalf("CreateAt returned error: %v", err)
	}

	assertFileContent(t, filepath.Join(cgroupPath, "memory.max"), strconv.Itoa(128*1024*1024))
}

func TestCreateAtWritesPidsMax(t *testing.T) {
	basePath := t.TempDir()

	cgroupPath, err := CreateAt(basePath, "pids", 64, 17, 50000, 100000)
	if err != nil {
		t.Fatalf("CreateAt returned error: %v", err)
	}

	assertFileContent(t, filepath.Join(cgroupPath, "pids.max"), "17")
}

func TestCreateAtWritesCPUMax(t *testing.T) {
	basePath := t.TempDir()

	cgroupPath, err := CreateAt(basePath, "cpu", 64, 32, 25000, 100000)
	if err != nil {
		t.Fatalf("CreateAt returned error: %v", err)
	}

	assertFileContent(t, filepath.Join(cgroupPath, "cpu.max"), "25000 100000")
}

func TestAttachWritesPIDToFakeCgroupProcs(t *testing.T) {
	basePath := t.TempDir()
	cgroupPath, err := CreateAt(basePath, "attach", 64, 32, 50000, 100000)
	if err != nil {
		t.Fatalf("CreateAt returned error: %v", err)
	}

	if err := Attach(cgroupPath, 4242); err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}

	assertFileContent(t, filepath.Join(cgroupPath, "cgroup.procs"), "4242")
}

func TestCleanupRemovesCgroupDirectory(t *testing.T) {
	basePath := t.TempDir()
	cgroupPath := filepath.Join(basePath, "argus-cleanup")
	if err := os.Mkdir(cgroupPath, 0755); err != nil {
		t.Fatalf("create fake cgroup directory: %v", err)
	}

	if err := Cleanup(cgroupPath); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}

	if _, err := os.Stat(cgroupPath); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%q) error = %v, want not exist", cgroupPath, err)
	}
}

func TestCreateAtInvalidBasePathReturnsError(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("base"), 0644); err != nil {
		t.Fatalf("write base file: %v", err)
	}

	got, err := CreateAt(filePath, "invalid", 64, 32, 50000, 100000)
	if err == nil {
		t.Fatalf("CreateAt(%q) returned path %q and nil error, want error", filePath, got)
	}
}

func TestCreateAtUnwritableBasePathReturnsError(t *testing.T) {
	basePath := t.TempDir()
	blockedPath := filepath.Join(basePath, "argus-unwritable")
	if err := os.WriteFile(blockedPath, []byte("already a file"), 0644); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	got, err := CreateAt(basePath, "unwritable", 64, 32, 50000, 100000)
	if err == nil {
		t.Fatalf("CreateAt returned path %q and nil error, want error", got)
	}
}

func TestCreateAtRejectsDuplicateRunID(t *testing.T) {
	basePath := t.TempDir()

	_, err := CreateAt(
		basePath,
		"duplicate",
		64,
		32,
		50000,
		100000,
	)
	if err != nil {
		t.Fatalf("first CreateAt returned error: %v", err)
	}

	_, err = CreateAt(
		basePath,
		"duplicate",
		256,
		9,
		10000,
		20000,
	)
	if err == nil {
		t.Fatal("second CreateAt returned nil error, want duplicate rejection")
	}
}

func TestCreateAtRejectsInvalidLimits(t *testing.T) {
	tests := []struct {
		name          string
		memoryLimitMB int
		pidsLimit     int
		cpuQuota      int
		cpuPeriod     int
	}{
		{
			name:          "zero memory limit",
			memoryLimitMB: 0,
			pidsLimit:     20,
			cpuQuota:      50000,
			cpuPeriod:     100000,
		},
		{
			name:          "negative memory limit",
			memoryLimitMB: -1,
			pidsLimit:     20,
			cpuQuota:      50000,
			cpuPeriod:     100000,
		},
		{
			name:          "zero PID limit",
			memoryLimitMB: 64,
			pidsLimit:     0,
			cpuQuota:      50000,
			cpuPeriod:     100000,
		},
		{
			name:          "negative PID limit",
			memoryLimitMB: 64,
			pidsLimit:     -1,
			cpuQuota:      50000,
			cpuPeriod:     100000,
		},
		{
			name:          "zero CPU quota",
			memoryLimitMB: 64,
			pidsLimit:     20,
			cpuQuota:      0,
			cpuPeriod:     100000,
		},
		{
			name:          "negative CPU quota",
			memoryLimitMB: 64,
			pidsLimit:     20,
			cpuQuota:      -1,
			cpuPeriod:     100000,
		},
		{
			name:          "zero CPU period",
			memoryLimitMB: 64,
			pidsLimit:     20,
			cpuQuota:      50000,
			cpuPeriod:     0,
		},
		{
			name:          "negative CPU period",
			memoryLimitMB: 64,
			pidsLimit:     20,
			cpuQuota:      50000,
			cpuPeriod:     -1,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateAt(
				t.TempDir(),
				"invalid-limits",
				tt.memoryLimitMB,
				tt.pidsLimit,
				tt.cpuQuota,
				tt.cpuPeriod,
			)
			if err == nil {
				t.Fatal("CreateAt returned nil error, want validation error")
			}
		})
	}
}

func TestCreateAtRejectsUnsafeRunIDs(t *testing.T) {
	tests := []string{
		"",
		".",
		"..",
		"../outside",
		"../../outside",
		"/tmp/outside",
		"nested/run",
	}

	for _, runID := range tests {
		runID := runID

		t.Run(runID, func(t *testing.T) {
			_, err := CreateAt(
				t.TempDir(),
				runID,
				64,
				20,
				50000,
				100000,
			)
			if err == nil {
				t.Fatalf("CreateAt accepted unsafe run ID %q", runID)
			}
		})
	}
}

func TestAttachRejectsInvalidPID(t *testing.T) {
	tests := []int{0, -1, -999}

	for _, pid := range tests {
		err := Attach(t.TempDir(), pid)
		if err == nil {
			t.Fatalf("Attach accepted invalid PID %d", pid)
		}
	}
}

func TestAttachMissingCgroupReturnsError(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing")

	err := Attach(missingPath, 4242)
	if err == nil {
		t.Fatal("Attach returned nil error for missing cgroup")
	}
}

func TestCleanupMissingPathReturnsError(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing")

	err := Cleanup(missingPath)
	if err == nil {
		t.Fatal("Cleanup returned nil error for missing path")
	}
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	got := string(data)
	if got != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}
