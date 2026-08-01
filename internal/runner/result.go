package runner

import "time"

type Result struct {
	RunID          string
	Status         string
	Output         string
	ErrorMessage   string
	Duration       time.Duration
	PID            int
	StartTime      time.Time
	EndTime        time.Time
	MonitorResults map[string]string
	SandboxPath    string
	SandboxKept    bool
}
