# SysTrace 2.0

`ptrace`-based Linux syscall monitor. Runs a target binary in an isolated namespace sandbox, traces its syscalls (including forked/cloned/exec'd children), and scores behavior with a weighted rule engine plus a Random Forest classifier.

## Features

- `ptrace` tracer with automatic `fork`/`vfork`/`clone`/`execve` following
- Namespace sandbox: new user/PID/mount namespace, `pivot_root`'d into a minimal rootfs
- Per-process and aggregate syscall statistics
- Rule-based detection with automatic `SIGKILL` enforcement
- Weighted risk scoring (0–100)
- Random Forest ML classifier (scikit-learn) as a secondary signal
- HTML report + JSON alert/feature logs + raw syscall trace



`config.sh` does the whole setup + build + run in one step: checks for `gcc`/`make`/`python3`, creates and activates a `.venv`, installs Python deps (`ml/requirements.txt` if present, else `numpy scikit-learn joblib`), runs `make clean && make`, then executes `./linux_syscall_monitor <target>`. `<target>` must already be a compiled ELF binary, same as manual usage below. No `ml/requirements.txt` currently ships in the repo, so the fallback install runs; `joblib` isn't actually imported by `predict.py`/`train.py` (both use `pickle`).

---
## Dashboard : 
![SysTrace dashboard](image/dashboardexmpl.png)
---
## Architecture

```
target binary
  → sandbox setup     (namespace.c, set_root.c: clone() + pivot_root)
  → ptrace tracer      (tracer.c: PTRACE_SYSCALL loop)
  → syscall monitors   (file/process/memory/network_monitor.c)
  → syscall stats      (stat.c: per-pid + aggregate)
  → rule engine         (rules.c: check_danger / check_rules, may SIGKILL)
  → risk score          (score.c: compute_risk_score)
  → features.json       (dataset.c)
  → ML prediction       (ml/predict.py → syscall_model.pkl)
  → security_report.html (dashboard/index.c)
```

## What It Monitors

| Category | Tracked syscalls | Notes |
| --- | --- | --- |
| File | `open`, `openat`, `read`, `close` | `write` is logged only, no counter/rule |
| Process | `execve`, `fork`, `clone`, `wait4`, `ptrace` | |
| Memory | `mmap`, `mprotect` | `munmap`, `brk` logged only |
| Network | `socket`, `connect`, `sendto`, `recvfrom`, `bind`, `listen`, `accept` | |

All syscalls (not just these) are written to `syscall.txt` via a name table in `syscall.c`, falling back to `"unknown"`.

## Detection & Rules

| Trigger | Condition | Action |
| --- | --- | --- |
| Sensitive file access | `open`/`openat` → `/etc/passwd` or `/etc/shadow` | Alert + `SIGKILL` |
| Excessive file opens | `open` > 100 (per PID) | Alert + `SIGKILL` |
| Excessive file reads | `read` > 29 (per PID) | Alert + `SIGKILL` |
| Excessive forking | `fork`/`clone` > 8 (per PID) | Alert + `SIGKILL` |
| Excessive re-exec | `execve` > 8 (per PID) | Alert + `SIGKILL` |
| Network connect | any `connect()` | Alert + `SIGKILL` |
| Network send | any tracked send | Alert + `SIGKILL` |
| Memory protection change | `mprotect` > 5 (per PID) | Alert + `SIGKILL` |
| Cross-process tracing | any `ptrace()` | Alert + `SIGKILL` |
| High weighted risk | `compute_risk_score()` ≥ 70 | Alert + `SIGKILL` |
| Moderate weighted risk | score in [40, 70) | Alert only |

`killit` counts `SIGKILL`s issued by the rule engine (per-PID and aggregate). It's a record of enforcement, not a rule itself — but it directly floors the risk score (below).

## Risk Scoring

```
score = (Σ count_i × weight_i) / (total_syscalls × 6.0) × 100
```

| Category | Weight | | Category | Weight |
| --- | --- | --- | --- | --- |
| `ptrace` | 6.0 | | `process` | 1.5 |
| `connect` | 5.0 | | `open` | 0.5 |
| `network` | 4.0 | | `memory` (mmap) | 0.5 |
| `execve` | 3.0 | | `file` | 0.3 |
| `mprotect` | 3.0 | | `read` | 0.2 |
| `fork` | 2.0 | | `close` | 0.1 |

If `killit > 0`, score floors at 90 regardless of the weighted sum. Zero syscalls → 90 if killed, else 0. Clamped to 100. The report's "Danger Level" further combines this with the ML prediction (`give_danger()` in `dashboard/index.c`).

## Machine Learning

- `save_dataset()` appends one JSON-Lines record to `features.json` per run (12 syscall counters + `program` + `label`). `label` is set automatically from whether `check_danger()` flagged anything — not hand-annotated.
- `main.c` runs `python3 ml/predict.py`, which loads `ml/syscall_model.pkl` (`RandomForestClassifier(n_estimators=200)`, trained by `ml/train.py`) and scores the latest record.
- Output (`BENIGN`/`MALICIOUS` + confidence) is written to `prediction.txt` and read back into the HTML report.
- Deps: `numpy`, `scikit-learn`. No training dataset ships in this repo, only the pretrained model. No published accuracy — treat the prediction as a secondary signal, not a verdict.

## Reports

| File | Written by | Mode | Contents |
| --- | --- | --- | --- |
| `security_report.html` | `dashboard/index.c` | overwrite | Summary, rule score, ML prediction, final danger % |
| `alerts.json` | `alert.c` | append | One JSON object per high-severity match |
| `features.json` | `dataset.c` | append | JSON-Lines syscall counts, ML input |
| `prediction.txt` | `ml/predict.py` | overwrite | Label + confidence |
| `log.txt` | `alert.c` | append | Plain-text alert messages |
| `syscall.txt` | `alert.c`/`tracer.c` | append | Raw ENTER/EXIT syscall trace |

Everything except `security_report.html`/`prediction.txt` accumulates across runs — `make clean` between traces.

## Project Structure

```
SysTrace/
├── src/          # tracer, sandbox, monitors, rules, scoring, dataset writer
├── include/      # headers
├── dashboard/    # index.c (HTML report) + style.css
├── ml/           # train.py, predict.py, syscall_model.pkl
├── tests/        # benign_*.c / mal_*.c sample programs
├── image/        # README assets
├── makefile
└── config.sh     # setup + build + run, see Quick Start
```

## Build

```
make          # build linux_syscall_monitor, basic_target, tests/bin/*
make clean    # remove binaries and all runtime output
make re       # clean + all
```

Deps: `gcc`, Linux headers. Sandbox uses `CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNS` — usually no root needed, but requires unprivileged user namespaces to be enabled.

## Usage

```
chmod +x config.sh

./config.sh ./path/to/binary
```
---

Argument must be a compiled ELF binary, not a `.c` file. `basic_target` (from `src/test.c`) exercises file I/O, `mmap`/`mprotect`, `ptrace`, `fork`, and `execve` in one run. Use `./config.sh ./path/to/binary` instead to build and run in one step (see Quick Start).



| Program | Behavior |
| --- | --- |
| `benign_idle.c` | Sleeps, exits — near-zero baseline |
| `benign_fileread.c` | Create/read/remove one temp file |
| `mal_fileopen.c` | Burst open/read/close of 30 files |
| `mal_forkbomb.c` | 15 children, capped and reaped |
| `mal_connect.c` | 12 `connect()` attempts to `127.0.0.1` |
| `mal_mmap_mprotect.c` | 20 rounds of `mmap` + `mprotect` to RX |

## Python Setup

`config.sh` handles this automatically in a `.venv` (see Quick Start). To do it manually instead:

```
pip install numpy scikit-learn
```

`ml/syscall_model.pkl` is already trained. To retrain: `python ml/train.py path/to/dataset.jsonl`.

## Example Output

```
REPORT: security_report.html created
Rule engine score: 78%
ML prediction: MALICIOUS
ML confidence: 91.42%
Final danger: 85%
Danger events: 3
```

## Security / Limitations

- Single-target dynamic analysis tool, not an EDR/HIDS — no persistent agent, no kernel-level enforcement.
- `check_danger()` dereferences `path` unconditionally; `connect()`'s exit handler always passes `path == NULL`, so tracing `connect()` can crash the monitor.
- Sandbox only copies in the target binary, `libc.so.6`, and `ld-linux-x86-64.so.2` at hardcoded non-multiarch paths — other dependencies or distro layouts won't run.
- Target is copied into the sandbox as a fixed `/basic_target`, but the tracer still `execvp()`s the original argv path — only matching invocations resolve after `pivot_root`.
- `fd_tables.c` is one global table shared across all traced processes, not scoped per PID.
- Enforcement is post-hoc `SIGKILL`, not syscall interception — the flagged call has already run.
- No training dataset or accuracy numbers ship with `syscall_model.pkl`.

Run only against binaries you own or have permission to inspect, preferably in a VM — the sandbox is not a hardened security boundary.

## Version

SysTrace 2.0