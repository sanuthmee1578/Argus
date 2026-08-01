package cli

import (
	"fmt"
	"io"
)

func PrintHelp(w io.Writer) {
	PrintBanner(w)

	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  argus <command> [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  run <script>       Execute a Python script securely")
	fmt.Fprintln(w, "  scan <script>      Scan a script without executing it")
	fmt.Fprintln(w, "  setup-rootfs       Build the isolated execution rootfs")
	fmt.Fprintln(w, "  doctor             Check whether Argus is ready")
	fmt.Fprintln(w, "  version            Display version information")
	fmt.Fprintln(w, "  help               Display this help")
}
