package sandbox

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

type PreparedSandbox struct {
	HostPath    string
	RuntimePath string
	ScriptName  string
}

func PrepareSandbox(scriptPath string, enableChroot bool, rootfsPath string) (PreparedSandbox, error) {
	var sandboxPath string
	timeStamp := time.Now().Format("2006-01-02T15-04-05.000")
	if enableChroot {
		sandboxPath = filepath.Join(rootfsPath, "sandbox", "run-"+timeStamp)
	} else {
		sandboxPath = filepath.Join(os.TempDir(), "argus", "run-"+timeStamp)
	}

	err := os.MkdirAll(sandboxPath, 0755)
	if err != nil {
		return PreparedSandbox{}, err
	}

	scriptName := filepath.Base(scriptPath)

	sandboxScriptPath := filepath.Join(sandboxPath, scriptName)

	err = CopyScript(scriptPath, sandboxScriptPath)

	if err != nil {
		return PreparedSandbox{}, err
	}

	err = os.Chmod(sandboxScriptPath, 0444)
	if err != nil {
		return PreparedSandbox{}, err
	}

	if enableChroot {
		return PreparedSandbox{
			HostPath:    sandboxPath,
			RuntimePath: filepath.Join("/sandbox", "run-"+timeStamp),
			ScriptName:  scriptName,
		}, nil
	} else {
		return PreparedSandbox{
			HostPath:    sandboxPath,
			RuntimePath: sandboxPath,
			ScriptName:  scriptName,
		}, nil
	}
}

func CopyScript(src string, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}
	return nil
}
