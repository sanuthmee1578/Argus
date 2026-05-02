# Architecture

Argus is scaffolded as a small Go application with a conventional split between the entrypoint, command layer, and internal packages.

## Layout

- `main.go` boots the application.
- `cmd/run.go` coordinates the top-level execution flow.
- `internal/logger` wraps basic logging behavior.
- `internal/policy` defines the policy model used by the runner.
- `internal/runner` owns the primary runtime loop.

## Notes

The repository includes `logs/` and `reports/` directories as tracked output targets, but generated files should stay out of version control.
