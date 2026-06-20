package seccomp

import (
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyNoNetworkProfile() error {
	return applyProfile(
		libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)),
		[]string{
			"reboot",
			"mount",
			"umount2",
			"ptrace",
			"setns",
			"unshare",
			"kexec_load",
			"socket",
			"connect",
			"accept",
			"bind",
			"listen",
			"sendto",
			"recvfrom",
		},
	)
}

func ApplyDefaultProfile() error {
	return applyProfile(
		libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)),
		defaultBlockedSyscalls(),
	)
}

func ApplyStrictProfile() error {
	return applyProfile(
		libseccomp.ActKillProcess,
		defaultBlockedSyscalls(),
	)
}

func defaultBlockedSyscalls() []string {
	return []string{
		"reboot",
		"mount",
		"umount2",
		"ptrace",
		"setns",
		"unshare",
		"kexec_load",
	}
}

func applyProfile(action libseccomp.ScmpAction, blockedSyscalls []string) error {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return err
	}

	for _, syscallName := range blockedSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(syscallName)
		if err != nil {
			return err
		}

		err = filter.AddRule(syscallID, action)
		if err != nil {
			return err
		}
	}

	return filter.Load()
}
