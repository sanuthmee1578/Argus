# Argus Examples

These scripts are small, controlled demos for exercising Argus policies.
Run them through Argus instead of running untrusted code directly:

```bash
./argus run examples/safe.py
./argus run examples/timeout.py
./argus run examples/memory.py
./argus run examples/network.py
./argus run examples/process_limit.py
./argus run examples/suspicious.py
```

## Demos

| Script | Purpose | Built-in control |
|---|---|---|
| `safe.py` | Successful baseline execution | Prints deterministic output and exits |
| `timeout.py` | Timeout enforcement | Sleeps for 20 seconds by default |
| `memory.py` | Memory limit enforcement | Allocates up to 128 MiB by default |
| `network.py` | Runtime network enforcement | Attempts one socket operation blocked by seccomp |
| `process_limit.py` | Process limit enforcement | Starts up to 48 short-lived child processes by default |
| `suspicious.py` | Static suspicious-pattern detection | Runs one harmless shell command if policy allows execution |

The process-limit demo is intentionally named `process_limit.py` in public
documentation. It is bounded and is not an uncontrolled process-spawning
payload.

`timeout.py`, `memory.py`, and `process_limit.py` accept one optional numeric
argument for local tuning. Each argument is clamped to a documented upper bound.
