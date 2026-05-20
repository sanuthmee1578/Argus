package policy

import (
	"encoding/json"
	"os"
)

type Policy struct {
	Timeout    int  `json:"timeout"`
	StrictMode bool `json:"strict_mode"`

	BlockedPatterns []string `json:"blocked_patterns"`

	MemoryLimitMB int `json:"memory_limit_mb"`
}

func Load() Policy {
	data, err := os.ReadFile("./config/policy.json")
	if err != nil {
		panic("Error reading policy file: " + err.Error())
	}

	var policy Policy

	error := json.Unmarshal(data, &policy)

	if error != nil {
		panic("Error parsing policy file: " + error.Error())
	}

	return policy

}
