package seccomp

import (
	"syscall"
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func TestDefaultBlockedSyscallsContainsExpectedEntries(t *testing.T) {
	blocked := syscallSet(defaultBlockedSyscalls())
	expected := []string{
		"reboot",
		"mount",
		"umount2",
		"ptrace",
		"setns",
		"unshare",
		"kexec_load",
	}

	for _, syscallName := range expected {
		if !blocked[syscallName] {
			t.Fatalf("defaultBlockedSyscalls() missing %q", syscallName)
		}
	}
}

func TestDefaultBlockedSyscallsHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}

	for _, syscallName := range defaultBlockedSyscalls() {
		if seen[syscallName] {
			t.Fatalf("defaultBlockedSyscalls() contains duplicate %q", syscallName)
		}
		seen[syscallName] = true
	}
}

func TestDefaultBlockedSyscallsExcludesSocket(t *testing.T) {
	if syscallSet(defaultBlockedSyscalls())["socket"] {
		t.Fatal("defaultBlockedSyscalls() includes socket")
	}
}

func TestNoNetworkBlockedSyscallsIncludesNetworkSyscalls(t *testing.T) {
	blocked := syscallSet(noNetworkBlockedSyscalls())
	expected := []string{
		"socket",
		"socketpair",
		"connect",
		"accept",
		"accept4",
		"bind",
		"listen",
		"sendto",
		"sendmsg",
		"sendmmsg",
		"recvfrom",
		"recvmsg",
		"recvmmsg",
		"shutdown",
		"getsockname",
		"getpeername",
		"setsockopt",
		"getsockopt",
	}

	for _, syscallName := range expected {
		if !blocked[syscallName] {
			t.Fatalf("noNetworkBlockedSyscalls() missing %q", syscallName)
		}
	}
}

func TestNoNetworkBlockedSyscallsHasNoDuplicates(t *testing.T) {
	seen := make(map[string]bool)

	for _, syscallName := range noNetworkBlockedSyscalls() {
		if seen[syscallName] {
			t.Fatalf("noNetworkBlockedSyscalls() contains duplicate %q", syscallName)
		}

		seen[syscallName] = true
	}
}

func TestProfileForNameMapsKnownProfiles(t *testing.T) {
	errnoAction := libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))
	tests := []struct {
		name             string
		wantAction       libseccomp.ScmpAction
		wantSyscallNames []string
	}{
		{
			name:             "default",
			wantAction:       errnoAction,
			wantSyscallNames: defaultBlockedSyscalls(),
		},
		{
			name:             "strict",
			wantAction:       libseccomp.ActKillProcess,
			wantSyscallNames: defaultBlockedSyscalls(),
		},
		{
			name:             "no-network",
			wantAction:       errnoAction,
			wantSyscallNames: noNetworkBlockedSyscalls(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := profileForName(tt.name)
			if err != nil {
				t.Fatalf("profileForName(%q) returned error: %v", tt.name, err)
			}
			if profile == nil {
				t.Fatalf("profileForName(%q) returned nil profile", tt.name)
			}
			if profile.name != tt.name {
				t.Fatalf("profileForName(%q) name = %q, want %q", tt.name, profile.name, tt.name)
			}
			if profile.action != tt.wantAction {
				t.Fatalf("profileForName(%q) action = %v, want %v", tt.name, profile.action, tt.wantAction)
			}
			if !sameSyscallNames(profile.blockedSyscalls, tt.wantSyscallNames) {
				t.Fatalf("profileForName(%q) syscalls = %v, want %v", tt.name, profile.blockedSyscalls, tt.wantSyscallNames)
			}
		})
	}
}

func TestProfileForNameMapsNoneToNoProfile(t *testing.T) {
	profile, err := profileForName("none")
	if err != nil {
		t.Fatalf("profileForName(%q) returned error: %v", "none", err)
	}
	if profile != nil {
		t.Fatalf("profileForName(%q) = %#v, want nil", "none", profile)
	}
}

func TestProfileForNameRejectsUnknownProfile(t *testing.T) {
	if _, err := profileForName("unknown"); err == nil {
		t.Fatal("profileForName() accepted unknown profile")
	}
}

func TestApplyProfileReturnsNilForNone(t *testing.T) {
	if err := ApplyProfile("none"); err != nil {
		t.Fatalf("ApplyProfile(%q) returned error: %v", "none", err)
	}
}

func TestApplyProfileRejectsUnknownProfile(t *testing.T) {
	if err := ApplyProfile("unknown"); err == nil {
		t.Fatal("ApplyProfile() accepted unknown profile")
	}
}

func syscallSet(syscalls []string) map[string]bool {
	set := make(map[string]bool, len(syscalls))
	for _, syscallName := range syscalls {
		set[syscallName] = true
	}
	return set
}

func sameSyscallNames(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	rightSet := syscallSet(right)
	for _, syscallName := range left {
		if !rightSet[syscallName] {
			return false
		}
	}
	return true
}
