package behavior

type Analysis struct {
	Pattern     string
	Risk        string
	Intent      string
	Explanation string
}
var behaviorMap = map[string]Analysis{
    "os.system": {
        Pattern: "os.system",
        Risk: "HIGH",
        Intent: "Shell command execution",
        Explanation: "Script may execute arbitrary system commands.",
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