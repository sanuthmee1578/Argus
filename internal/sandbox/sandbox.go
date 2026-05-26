package sandbox

import (
	"os"
	"path/filepath"
	"time"
)

type PreparedSandbox struct {
	Path       string
	ScriptName string
}

func PrepareSandbox(scriptPath string) (PreparedSandbox, error) {
	timeStamp := time.Now().Format("2006-01-02T15-04-05.000")
	sandboxPath := filepath.Join("sandbox", "run-"+timeStamp)
	err := os.MkdirAll(sandboxPath, 0755)
	if err != nil {
		return PreparedSandbox{}, err
	}

	scriptName := filepath.Base(scriptPath)

	return PreparedSandbox{
		Path:       sandboxPath,
		ScriptName: scriptName,
	}, nil
}
