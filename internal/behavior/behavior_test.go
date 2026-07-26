package behavior

import (
	"reflect"
	"testing"
)

func TestAnalyze(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		warnings []string
		want     []Analysis
	}{
		{
			name: "known warning",
			warnings: []string{
				"os.system",
			},
			want: []Analysis{
				{
					Pattern:     "os.system",
					Risk:        "HIGH",
					Intent:      "Shell execution",
					Explanation: "Script may execute arbitrary system commands.",
				},
			},
		},
		{
			name: "unknown warning is ignored",
			warnings: []string{
				"unknown.pattern",
			},
		},
		{
			name: "multiple warnings preserve input order",
			warnings: []string{
				"socket.connect",
				"requests.get",
				"os.system",
			},
			want: []Analysis{
				{
					Pattern:     "socket.connect",
					Risk:        "HIGH",
					Intent:      "Raw socket",
					Explanation: "Script opens a direct network connection.",
				},
				{
					Pattern:     "requests.get",
					Risk:        "MEDIUM",
					Intent:      "Network call",
					Explanation: "Script makes outbound HTTP requests.",
				},
				{
					Pattern:     "os.system",
					Risk:        "HIGH",
					Intent:      "Shell execution",
					Explanation: "Script may execute arbitrary system commands.",
				},
			},
		},
		{
			name: "empty warnings",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Analyze(tt.warnings)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Analyze() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
