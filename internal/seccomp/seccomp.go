package seccomp

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyDefaultProfile() error {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return err
	}

	mountSyscall, err := libseccomp.GetSyscallFromName("mount")
	if err != nil {
		return err
	}

	err = filter.AddRule(mountSyscall, libseccomp.ActKill)
	if err != nil {
		return err
	}

	return filter.Load()
}
