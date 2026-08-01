package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestPrintVersionIncludesVersionAndPlatform(t *testing.T) {
	var output bytes.Buffer

	PrintVersion(&output)

	text := output.String()
	if !strings.Contains(text, Version) {
		t.Fatalf("version output missing version %q:\n%s", Version, text)
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !strings.Contains(text, platform) {
		t.Fatalf("version output missing platform %q:\n%s", platform, text)
	}
}
