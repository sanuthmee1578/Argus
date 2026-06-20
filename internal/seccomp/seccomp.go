package seccomp

import (
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyDefaultProfile() error {
	return applyProfile(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
}

func ApplyStrictProfile() error {
	return applyProfile(libseccomp.ActKillProcess)
}

func applyProfile(action libseccomp.ScmpAction) error {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return err
	}

	blockedSyscalls := []string{
		"reboot",
		"mount",
		"umount2",
		"ptrace",
		"setns",
		"unshare",
		"kexec_load",
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
