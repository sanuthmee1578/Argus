# Argus — Secure Runtime for AI-Generated & Untrusted Code

## Overview

Argus is a policy-driven, Linux-based runtime designed to safely execute untrusted or AI-generated code. It provides a controlled execution environment that combines static analysis, runtime monitoring, and system-level enforcement to prevent unsafe behavior.

As AI-assisted development becomes widespread, developers increasingly run unfamiliar code. Argus bridges the gap between **code generation and safe execution**, ensuring that potentially harmful scripts cannot compromise the host system.

---

## Problem

Modern development workflows introduce new risks:

- Running AI-generated or unknown scripts
- Infinite loops causing CPU exhaustion
- Unauthorized file access (e.g., SSH keys)
- Data exfiltration via network calls
- Dependency vulnerabilities
- Lack of visibility into runtime behavior

Traditional tools are either too complex (cloud sandboxes) or too limited (simple script runners).

---

## Solution

Argus introduces a **multi-layered execution pipeline**:

- Static scanning (SAST-lite) before execution
- Policy-based execution control
- Linux-level isolation and constraints
- Runtime monitoring (CPU, time, process behavior)
- Automatic enforcement (kill/limit unsafe processes)
- Structured logging and reporting

---

## Core Features

### Execution Engine
- Run scripts through a controlled Go runtime
- Intercept execution via CLI (`argus run <script>`)

### Policy Engine
- Configurable execution profiles (safe, ml, strict)
- Rules for:
  - Timeout
  - CPU usage
  - Memory limits
  - Network access
  - File system permissions

### Runtime Monitoring
- Track process lifecycle
- Detect abnormal behavior:
  - Infinite loops
  - Resource spikes
  - Unexpected process spawning

### Enforcement Layer
- Kill or restrict processes when policy is violated
- Prevent system damage in real-time

### Static Analysis (SAST-lite)
- Detect risky patterns before execution:
  - `rm -rf`
  - `os.system`
  - infinite loops
  - unsafe subprocess usage

### Dependency Analysis (SCA-lite)
- Scan dependencies (e.g., `requirements.txt`)
- Identify risky or unknown packages

### Logging & Reporting
- Store execution results in structured logs
- Provide audit trails for every run

---

## System Architecture
User (CLI)
↓
Command Interface (argus run / scan)
↓
Policy Engine (rules, profiles)
↓
Static Analyzer (SAST-lite)
↓
Execution Engine (Go runtime)
↓
Linux Control Layer
├── Process Control (exec, kill)
├── Resource Limits (ulimit / cgroups)
├── Isolation (namespaces - future)
↓
Runtime Monitor
↓
Enforcement Engine
↓
Logger & Reporter


---

## Execution Flow

1. User runs:

```bash
argus run script.py
---

2. Argus:
Parses CLI input
Loads execution policy
Performs static scan (optional)
Creates controlled execution context
Executes script via Go runtime
Monitors runtime behavior
Applies enforcement if needed:
Timeout
Resource violation
Classifies result:
SUCCESS
ERROR
TIMEOUT
BLOCKED
Writes logs and report

