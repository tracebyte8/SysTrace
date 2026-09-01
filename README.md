# SysTrace 2.0

`ptrace`-based Linux syscall monitor and sandbox for analyzing ELF binaries.

SysTrace runs a target inside an isolated Linux namespace environment, traces its system calls and child processes, applies rule-based detection and weighted risk scoring, then uses a Random Forest classifier as a secondary signal.

## Features

- `ptrace` syscall tracing
- Follows `fork`, `vfork`, `clone`, and `execve`
- Linux user, PID, and mount namespaces
- Minimal `pivot_root` sandbox
- File, process, memory, and network monitoring
- Per-process and aggregate syscall statistics
- Rule-based detection with `SIGKILL` enforcement
- Weighted risk score from 0–100
- Random Forest ML classification
- HTML security report
- JSON and text logs
- Raw syscall trace

## Quick Start

Clone the repository:

```bash
git clone https://github.com/tracebyte8/SysTrace.git
cd SysTrace
```

Make the configuration script executable:

```bash
chmod +x config.sh
```

Run SysTrace against a compiled ELF binary:

```bash
./config.sh ./tests/bin/mal_fileopen
```

`config.sh` automatically:

1. Checks `gcc`, `make`, and `python3`
2. Creates `.venv`
3. Installs the required Python dependencies
4. Builds SysTrace
5. Runs the target through the monitor
6. Generates the security report

No manual Python package installation is required.

> The target must be an already compiled ELF binary. A `.c` source file cannot be passed directly.

## Architecture

```text
Target ELF
    │
    ▼
Namespace Sandbox
    │
    ├── CLONE_NEWUSER
    ├── CLONE_NEWPID
    ├── CLONE_NEWNS
    └── pivot_root
    │
    ▼
ptrace Tracer
    │
    ├── Syscall tracing
    ├── fork/vfork/clone following
    └── exec following
    │
    ▼
System Call Monitors
    │
    ├── File
    ├── Process
    ├── Memory
    └── Network
    │
    ▼
Statistics
    │
    ▼
Rule Engine
    │
    ├── Alerts
    └── SIGKILL enforcement
    │
    ▼
Risk Scoring
    │
    ├── features.json
    │
    └── Random Forest
             │
             ▼
      security_report.html
```

## What It Monitors

| Category | Tracked syscalls |
|---|---|
| File | `open`, `openat`, `read`, `close` |
| Process | `execve`, `fork`, `clone`, `wait4`, `ptrace` |
| Memory | `mmap`, `mprotect` |
| Network | `socket`, `connect`, `sendto`, `recvfrom`, `bind`, `listen`, `accept` |

Other syscalls are also written to `syscall.txt` when their names are available in the syscall table.

## Detection Rules

| Trigger | Condition | Action |
|---|---|---|
| Sensitive file access | `/etc/passwd` or `/etc/shadow` | Alert + `SIGKILL` |
| Excessive file opens | `open` > 100 | Alert + `SIGKILL` |
| Excessive reads | `read` > 29 | Alert + `SIGKILL` |
| Excessive forking | `fork`/`clone` > 8 | Alert + `SIGKILL` |
| Excessive re-execution | `execve` > 8 | Alert + `SIGKILL` |
| Network connection | Any `connect()` | Alert + `SIGKILL` |
| Network send | Tracked send syscall | Alert + `SIGKILL` |
| Memory protection change | `mprotect` > 5 | Alert + `SIGKILL` |
| Cross-process tracing | Any `ptrace()` | Alert + `SIGKILL` |
| High risk | Score ≥ 70 | Alert + `SIGKILL` |
| Moderate risk | 40 ≤ score < 70 | Alert |

`killit` records `SIGKILL` actions performed by the rule engine.

## Risk Scoring

SysTrace calculates a weighted behavioral score:

```text
score =
    (sum of weighted syscall counts)
    / (total syscalls × 6.0)
    × 100
```

The score is clamped to `0–100`.

If the rule engine kills a process, the risk score is forced to at least `90`.

### Weights

| Behavior | Weight |
|---|---:|
| `ptrace` | 6.0 |
| `connect` | 5.0 |
| network | 4.0 |
| `execve` | 3.0 |
| `mprotect` | 3.0 |
| `fork` | 2.0 |
| process | 1.5 |
| `open` | 0.5 |
| `mmap` | 0.5 |
| file | 0.3 |
| `read` | 0.2 |
| `close` | 0.1 |

## Machine Learning

SysTrace uses a Random Forest classifier as a secondary behavioral signal.

The model is located at:

```text
ml/syscall_model.pkl
```

The monitored syscall statistics are exported to:

```text
features.json
```

`ml/predict.py` reads the latest feature record and produces:

```text
prediction.txt
```

Example:

```text
Program: ./tests/bin/mal_fileopen

Prediction: MALICIOUS
Confidence: 91.42%
```

The ML result should be treated as a **secondary signal**, not a definitive verdict.

The repository does not ship the original training dataset or published model accuracy.

## Reports and Logs

| File | Description |
|---|---|
| `security_report.html` | Final HTML security report |
| `alerts.json` | JSON security alerts |
| `features.json` | ML feature records |
| `prediction.txt` | Latest ML prediction |
| `log.txt` | Human-readable alerts |
| `syscall.txt` | Raw syscall trace |

`features.json`, `alerts.json`, `log.txt`, and `syscall.txt` accumulate records across runs.

`security_report.html` and `prediction.txt` are overwritten on each run.

## Dashboard

![SysTrace Dashboard](image/dashboardexmpl.png)

The HTML report contains:

- Rule engine score
- ML prediction
- ML confidence
- Final danger percentage
- Security events
- Behavioral statistics

## Project Structure

```text
SysTrace/
├── src/
│   ├── tracer.c
│   ├── namespace.c
│   ├── set_root.c
│   ├── file_monitor.c
│   ├── process_monitor.c
│   ├── memory_monitor.c
│   ├── network_monitor.c
│   ├── rules.c
│   ├── score.c
│   ├── stat.c
│   └── dataset.c
│
├── include/
├── dashboard/
│   ├── index.c
│   └── style.css
│
├── ml/
│   ├── train.py
│   ├── predict.py
│   └── syscall_model.pkl
│
├── tests/
│   └── bin/
│
├── image/
├── Makefile
├── config.sh
└── README.md
```

## Build Manually

If you do not want to use `config.sh`:

```bash
make
```

Clean the project:

```bash
make clean
```

Rebuild:

```bash
make re
```

Manual Python setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install numpy scikit-learn
```

## Test Programs

| Program | Behavior |
|---|---|
| `benign_idle.c` | Sleeps and exits |
| `benign_fileread.c` | Creates, reads, and removes a temporary file |
| `mal_fileopen.c` | Opens/reads/closes multiple files |
| `mal_forkbomb.c` | Creates a capped number of children |
| `mal_connect.c` | Attempts multiple network connections |
| `mal_mmap_mprotect.c` | Repeated `mmap`/`mprotect` operations |

Example:

```bash
./config.sh ./tests/bin/mal_forkbomb
```

Then open:

```bash
xdg-open security_report.html
```

## Security and Limitations

SysTrace is a **research/learning dynamic-analysis tool**, not a hardened security boundary or production EDR.

Important limitations:

- Only a single target is analyzed per run.
- Enforcement occurs through `SIGKILL` after detection; it is not kernel-level syscall blocking.
- The sandbox uses Linux user/PID/mount namespaces and `pivot_root`.
- Unprivileged user namespaces must be enabled.
- The minimal root filesystem contains only the target and selected runtime libraries.
- Dynamically linked binaries with additional dependencies may fail inside the sandbox.
- The sandbox runtime currently assumes x86-64 library paths.
- File-descriptor tracking is global rather than PID-scoped.
- The ML model has no published accuracy guarantee.
- The rule engine and ML classifier can produce false positives and false negatives.
- The sandbox should not be treated as a replacement for a VM or hardened container.

Run SysTrace only against binaries you own or are authorized to analyze.

For untrusted binaries, use a dedicated VM or other appropriately isolated environment.

## Version

**SysTrace 2.0**