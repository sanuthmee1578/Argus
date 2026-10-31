package cli

import (
	"fmt"
	"io"
)

var Version = "0.1.0-dev"

func PrintBanner(w io.Writer) {
	fmt.Fprint(w, "\n"+
		"    ___\n"+
		"   /   |  _________ ___  _______\n"+
		"  / /| | / ___/ __ `/ / / / ___/\n"+
		" / ___ |/ /  / /_/ / /_/ (__  )\n"+
		"/_/  |_/_/   \\__, /\\__,_/____/\n"+
		"            /____/\n"+
		"\n"+
		"Argus Secure Execution Runtime\n\n")
}
