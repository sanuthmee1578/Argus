package cli

import (
	"fmt"
	"io"
	"runtime"
)

func PrintVersion(w io.Writer) {
	PrintBanner(w)

	fmt.Fprintf(w, "Version:  %s\n", Version)
	fmt.Fprintf(w, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
