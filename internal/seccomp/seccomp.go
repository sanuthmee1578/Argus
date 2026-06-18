package seccomp

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyDefaultProfile() error {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return err
	}

	return filter.Load()
}
