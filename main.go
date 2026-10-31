package main

import (
	"argus/internal/cli"
	"argus/internal/policy"
	"argus/internal/rootfs"
	"fmt"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		cli.PrintHelp(os.Stdout)
		return
	}
	command := os.Args[1]

	if command == "setup-rootfs" && len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, "Usage: argus setup-rootfs")
		os.Exit(cli.ExitGeneralError)
	}
	var policyPath string

	switch command {
	case "doctor", "scan", "run", "clean", "setup-rootfs":
		var err error
		policyPath, err = cli.ResolveDefaultPolicyPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Configuration error:", err)
			os.Exit(cli.ExitGeneralError)
		}
	}

	switch command {
	case "help", "--help", "-h":
		cli.PrintHelp(os.Stdout)
		return

	case "version", "--version", "-v":
		cli.PrintVersion(os.Stdout)
		return

	case "doctor":
		exitCode := cli.RunDoctor(
			os.Stdout,
			policyPath,
		)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return

	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintln(
				os.Stderr,
				"Usage: argus scan <script>",
			)
			os.Exit(cli.ExitGeneralError)
		}

		exitCode := cli.RunScan(
			os.Stdout,
			policyPath,
			os.Args[2],
		)

		os.Exit(exitCode)

	case "run":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: argus run <script>")
			os.Exit(cli.ExitGeneralError)
		}

		os.Exit(cli.RunScript(
			os.Stdin,
			os.Stdout,
			os.Stderr,
			policyPath,
			os.Args[2],
		))

	case "inspect":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: argus inspect <run-id>")
			os.Exit(cli.ExitGeneralError)
		}

		os.Exit(cli.RunInspect(
			os.Stdout,
			os.Stderr,
			"reports",
			os.Args[2],
		))

	case "clean":
		if len(os.Args) > 2 {
			fmt.Fprintln(os.Stderr, "Usage: argus clean")
			os.Exit(cli.ExitGeneralError)
		}

		os.Exit(cli.RunClean(
			os.Stdout,
			os.Stderr,
			policyPath,
		))
	}

	if command == "setup-rootfs" {
		loadPolicy, err := policy.Load(policyPath)
		if err != nil {
			fmt.Println("Failed to load policy:", err)
			os.Exit(1)
		}

		if os.Geteuid() != 0 {
			fmt.Println("Rootfs setup requires root privileges. Run with sudo.")
			return
		}

		err = rootfs.Setup(loadPolicy.RootfsPath)
		if err != nil {
			fmt.Println("Error setting up rootfs:", err)
			return
		}
		fmt.Println("Rootfs setup completed successfully.")
		return
	}

	fmt.Println("Unknown command:", command)
}
