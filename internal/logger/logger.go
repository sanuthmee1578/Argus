package logger

import stdlog "log"

type Logger struct{}

func New() *Logger {
	return &Logger{}
}

func (l *Logger) Info(message string) {
	stdlog.Println("INFO:", message)
}

func (l *Logger) Error(message string) {
	stdlog.Println("ERROR:", message)
}
