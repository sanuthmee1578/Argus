package runner

import (
	"fmt"

	"argus/internal/logger"
	"argus/internal/policy"
)

type Runner struct {
	log      *logger.Logger
	policies policy.Set
}

func New(log *logger.Logger, policies policy.Set) *Runner {
	return &Runner{log: log, policies: policies}
}

func (r *Runner) Run() error {
	r.log.Info("argus runner started")
	if len(r.policies) == 0 {
		return fmt.Errorf("no policies configured")
	}
	return nil
}
