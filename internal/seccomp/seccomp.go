package seccomp

import (
	"fmt"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

type profileDefinition struct {
	name            string
	action          libseccomp.ScmpAction
	blockedSyscalls []string
}

func ApplyProfile(name string) error {
	profile, err := profileForName(name)
	if err != nil {
		return err
	}
	if profile == nil {
		return nil
	}

	return applyProfile(profile.action, profile.blockedSyscalls)
}

func ApplyNoNetworkProfile() error {
	return ApplyProfile("no-network")
}

func ApplyDefaultProfile() error {
	return ApplyProfile("default")
}

func ApplyStrictProfile() error {
	return ApplyProfile("strict")
}

func profileForName(name string) (*profileDefinition, error) {
	errnoAction := libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))

	switch name {
	case "default":
		return &profileDefinition{
			name:            "default",
			action:          errnoAction,
			blockedSyscalls: defaultBlockedSyscalls(),
		}, nil
	case "strict":
		return &profileDefinition{
			name:            "strict",
			action:          libseccomp.ActKillProcess,
			blockedSyscalls: defaultBlockedSyscalls(),
		}, nil
	case "no-network":
		return &profileDefinition{
			name:            "no-network",
			action:          errnoAction,
			blockedSyscalls: noNetworkBlockedSyscalls(),
		}, nil
	case "none":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown seccomp profile: %s", name)
	}
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

func noNetworkBlockedSyscalls() []string {
	blockedSyscalls := append(
		[]string{},
		defaultBlockedSyscalls()...,
	)

	blockedSyscalls = append(
		blockedSyscalls,
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
	)

	return blockedSyscalls
}

func applyProfile(action libseccomp.ScmpAction, blockedSyscalls []string) error {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("create seccomp filter: %w", err)
	}
	defer filter.Release()

	for _, syscallName := range blockedSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(syscallName)
		if err != nil {
			return fmt.Errorf("resolve syscall %q: %w", syscallName, err)
		}

		if err := filter.AddRule(syscallID, action); err != nil {
			return fmt.Errorf("add seccomp rule for %q: %w", syscallName, err)
		}
	}

	if err := filter.Load(); err != nil {
		return fmt.Errorf("load seccomp filter: %w", err)
	}

	return nil
}
