package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDoctorInvalidPolicy(t *testing.T) {
	var output bytes.Buffer

	exitCode := RunDoctor(&output, "missing-policy.json")

	if exitCode != ExitGeneralError {
		t.Fatalf("RunDoctor() exit = %d, want %d", exitCode, ExitGeneralError)
	}

	text := output.String()
	if !strings.Contains(text, "Environment check") {
		t.Fatalf("doctor output missing heading:\n%s", text)
	}
	if !strings.Contains(text, "[FAIL] Policy configuration") {
		t.Fatalf("doctor output missing policy failure:\n%s", text)
	}
}
