package cmd

import (
	"fmt"

	"argus/internal/logger"
	"argus/internal/policy"
	"argus/internal/runner"
)

func Run() error {
	log := logger.New()
	policies := policy.DefaultSet()
	r := runner.New(log, policies)

	if err := r.Run(); err != nil {
		return fmt.Errorf("run argus: %w", err)
	}

	return nil
}
