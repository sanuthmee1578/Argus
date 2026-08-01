package runner

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestIsSeccompNetworkViolation(t *testing.T) {
	output := "Traceback\nPermissionError: [Errno 1] Operation not permitted\n"

	if !isSeccompNetworkViolation(output, true, "no-network") {
		t.Fatal("expected no-network seccomp PermissionError to be a security violation")
	}
	if isSeccompNetworkViolation(output, false, "no-network") {
		t.Fatal("disabled seccomp should not be a security violation")
	}
	if isSeccompNetworkViolation(output, true, "default") {
		t.Fatal("non-network profile should not be a network security violation")
	}
	if isSeccompNetworkViolation("exit status 1", true, "no-network") {
		t.Fatal("generic failures should not be security violations")
	}
}

func TestConfigureCgroupPlacement(t *testing.T) {
	cgroupDir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open fake cgroup directory: %v", err)
	}
	defer cgroupDir.Close()

	cmd := exec.Command("python3", "script.py")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	configureCgroupPlacement(cmd, cgroupDir)

	if !cmd.SysProcAttr.UseCgroupFD {
		t.Fatal("UseCgroupFD = false, want true")
	}
	if cmd.SysProcAttr.CgroupFD != int(cgroupDir.Fd()) {
		t.Fatalf("CgroupFD = %d, want %d", cmd.SysProcAttr.CgroupFD, int(cgroupDir.Fd()))
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("configureCgroupPlacement should preserve existing SysProcAttr fields")
	}
}
