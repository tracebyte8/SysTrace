# SysTrace

**A Linux system-call monitoring and behavioral security analysis tool combining `ptrace`-based tracing, lightweight namespace isolation, and machine learning classification.**

SysTrace observes the runtime behavior of a target program at the system-call level, extracts behavioral features, and classifies the observed activity as benign or malicious using a trained Random Forest model. It is built primarily in C for low-level tracing and isolation, with a Python/scikit-learn component for classification and reporting.

---

## Overview

SysTrace traces a target process using `ptrace`, capturing system calls related to file access, process creation, network activity, and memory operations. The captured behavior is aggregated into syscall statistics and a feature vector, which is passed to a trained Random Forest classifier to produce a benign/malicious prediction. Results are compiled into a structured HTML security report.

The project also includes a lightweight sandboxing layer built on Linux namespaces, used to isolate the target process during tracing.

---

## Architecture

```
Target Program
      ↓
Linux Namespace / Lightweight Sandbox
      ↓
ptrace-based System Call Monitor
      ↓
File / Process / Network / Memory Monitoring
      ↓
Syscall Statistics + Security Rules
      ↓
Feature Vector
      ↓
Random Forest ML Model
      ↓
Benign / Malicious Classification
      ↓
HTML Security Report
```

---

## Core Features

### System-Call Tracing
- Built on Linux `ptrace` to attach to and inspect target processes, including syscall arguments and registers.
- Tracks a broad set of syscalls across four behavioral categories:
  - **File operations** — `open`/`openat`, `read`, `close`, `chmod`
  - **Process activity** — `execve`, `fork`, `clone`, `kill`
  - **Network activity** — `socket`, `connect`
  - **Memory activity** — `mmap`, `mprotect`
- Maintains file-descriptor tracking to associate open file descriptors with their originating filenames.

### Rule-Based Detection
Heuristic rules flag suspicious behavioral patterns, including:
- Access to sensitive files
- Excessive file operations
- Excessive process creation
- Suspicious memory behavior (e.g. unusual `mmap`/`mprotect` usage)
- Suspicious network activity

### Lightweight Sandbox / Isolation Layer
An isolation layer built directly on Linux namespace primitives:
- `clone()` with `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNS`
- Mount namespace configuration via `MS_PRIVATE`
- Root filesystem switching with `pivot_root` and `umount2`
- `tmpfs`-backed minimal root filesystem, constructed at runtime under `/tmp/systrace-root`

This provides basic process, PID, and mount isolation for the traced target — it is **not** a container runtime replacement.

### Machine Learning Classification
- Feature vectors are derived from syscall statistics, with fields including:
  `file, process, network, fork, connect, execve, read, open, close, memory, chmod, kill, label`
- A `RandomForestClassifier` (scikit-learn) is trained on these vectors to distinguish benign from malicious behavior.
- The trained model is serialized to `ml/syscall_model.pkl`.
- The  [`DATASET`](https://github.com/tracebyte8/dataset_ebpf_syscall_derived.csv)

### Reporting
- Structured output as `features.json` (raw feature data) and `report.html` (human-readable report).
- The HTML report summarizes monitored activity, triggered security rules/events, syscall statistics, and the final ML classification.

---

## Example Feature Vector

```
[file, process, network, fork, connect, execve, read, open, close, memory, chmod, kill]
[15,   2,       0,       0,    0,       2,      1,    10,   4,     14,     6,     0]
```

---

## Technologies

| Category | Stack |
|---|---|
| Core tracer | C, Linux `ptrace` |
| Isolation | Linux namespaces, `clone`, mount namespaces, `pivot_root`, `tmpfs` |
| Machine learning | Python, scikit-learn, Random Forest |
| Data / output | JSON, HTML |
| Build | Make |

---

## Project Structure

```
linux-syscall-monitor/
├── include/
├── src/
│   ├── tracer.c            # Core ptrace-based syscall tracer
│   ├── syscall.c           # Syscall interception/handling
│   ├── namespace.c         # Namespace/clone setup
│   ├── set_root.c          # pivot_root / minimal rootfs setup
│   ├── file_monitor.c      # File operation monitoring
│   ├── process_monitor.c   # Process creation/execution monitoring
│   ├── network_monitor.c   # Network activity monitoring
│   ├── memory_monitor.c    # Memory-related activity monitoring
│   ├── fd_tables.c         # File descriptor tracking
│   ├── rules.c             # Rule-based detection logic
│   ├── alert.c             # Security alert generation
│   ├── stat.c               # Syscall statistics aggregation
│   └── dataset.c           # Feature vector / dataset generation
├── ml/
│   ├── train.py             # Random Forest training script
│   ├── predict.py           # Classification / inference script
│   └── syscall_model.pkl    # Trained model
├── dashboard/                # Report/dashboard assets
├── tests/
├── Makefile
├── dataset.csv
└── README.md
```

---

## Limitations

- The sandbox is an **educational, lightweight isolation layer** — it is not a production-grade container runtime and is not a hardened malware analysis sandbox.
- Namespace isolation covers user, PID, and mount namespaces only; it does not implement network namespace isolation, seccomp filtering, or cgroup resource limits.
- `ptrace`-based tracing introduces observable overhead and is detectable/evadable by sufficiently sophisticated malware.
- The ML classifier is trained on a limited feature set (aggregate syscall counts) and dataset; classification accuracy depends on the quality and diversity of training data.
- Not intended for tracing untrusted or genuinely malicious binaries outside of a properly isolated research environment.

---

## Security Disclaimer

SysTrace is a research and learning project exploring Linux internals, system-call tracing, namespace-based isolation, and behavioral malware detection using machine learning. It is **not** a certified or production-ready security tool and should not be relied upon as the sole defense against malicious software. Use in isolated, controlled environments only.

---

## Purpose

This project was built to explore and demonstrate:
- Linux internals and system-call tracing with `ptrace`
- Process, file, network, and memory monitoring
- Filesystem isolation using Linux namespaces (`clone`, `pivot_root`, mount namespaces)
- Sandbox architecture design
- Behavioral security analysis
- Applying machine learning (Random Forest) to cybersecurity classification problems