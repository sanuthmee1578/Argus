package behavior

type Analysis struct {
	Pattern     string
	Risk        string
	Intent      string
	Explanation string
}

var behaviorMap = map[string]Analysis{
	"os.system": {
		Pattern:     "os.system",
		Risk:        "HIGH",
		Intent:      "Shell execution",
		Explanation: "Script may execute arbitrary system commands.",
	},
	"subprocess.Popen": {
		Pattern:     "subprocess.Popen",
		Risk:        "HIGH",
		Intent:      "Subprocess abuse",
		Explanation: "Script spawns external child processes.",
	},
	"requests.get": {
		Pattern:     "requests.get",
		Risk:        "MEDIUM",
		Intent:      "Network call",
		Explanation: "Script makes outbound HTTP requests.",
	},
	"open('/etc/": {
		Pattern:     "open('/etc/",
		Risk:        "MEDIUM",
		Intent:      "System file read",
		Explanation: "Script accesses system configuration files.",
	},
	"open('~/.ssh": {
		Pattern:     "open('~/.ssh",
		Risk:        "HIGH",
		Intent:      "Credential harvesting",
		Explanation: "Script attempts to read SSH keys.",
	},
	"socket.connect": {
		Pattern:     "socket.connect",
		Risk:        "HIGH",
		Intent:      "Raw socket",
		Explanation: "Script opens a direct network connection.",
	},
	"rm -rf": {
		Pattern:     "rm -rf",
		Risk:        "HIGH",
		Intent:      "Destructive file operation",
		Explanation: "Script may delete files recursively.",
	},
	"/etc/": {
		Pattern:     "/etc/",
		Risk:        "MEDIUM",
		Intent:      "System file access",
		Explanation: "Script accesses system configuration files.",
	},
	"/home/": {
		Pattern:     "/home/",
		Risk:        "MEDIUM",
		Intent:      "User file access",
		Explanation: "Script accesses user files.",
	},
	"~/.ssh": {
		Pattern:     "~/.ssh",
		Risk:        "HIGH",
		Intent:      "Credential harvesting",
		Explanation: "Script attempts to read SSH keys.",
	},
	".env": {
		Pattern:     ".env",
		Risk:        "HIGH",
		Intent:      "Environment variable access",
		Explanation: "Script attempts to read environment variables.",
	},
	"id_rsa": {
		Pattern:     "id_rsa",
		Risk:        "HIGH",
		Intent:      "Credential harvesting",
		Explanation: "Script attempts to read private SSH keys.",
	},
}

func Analyze(warnings []string) []Analysis {
	var results []Analysis
	for _, warning := range warnings {
		analysis, found := behaviorMap[warning]
		if found {
			results = append(results, analysis)
		}
	}
	return results
}
