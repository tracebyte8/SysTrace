# Linux System Call Monitor

<p align="center">

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![GCC](https://img.shields.io/badge/GCC-CC342D?style=for-the-badge&logo=gnu&logoColor=white)
![ptrace](https://img.shields.io/badge/ptrace-System%20Calls-blue?style=for-the-badge)
![HTML](https://img.shields.io/badge/HTML-Report-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</p>

A lightweight **Linux System Call Monitor** written in **C** using the Linux **ptrace** API.

This project traces a running process, intercepts Linux system calls, and generates an **HTML report** describing file activity, process creation, memory operations, and network events.

The project was built for educational purposes to better understand:

- Linux internals
- Process tracing
- ptrace
- System calls
- Operating Systems

---

# Features

## Process Monitor

Tracks process-related system calls.

Supported:

- `execve`
- `fork`
- `waitpid`

---

## File Monitor

Tracks file activity.

Supported:

- `open`
- `openat`
- `read`
- `close`

---

## Memory Monitor

Tracks memory management.

Supported:

- `mmap`
- `mprotect`
- `munmap`

---

## Network Monitor

Current progress:

- socket
- bind
- listen
- accept
- connect
- send
- recv


---

## HTML Report

After execution the monitor generates an HTML report containing:

- Process activity
- File operations
- Memory operations
- Network operations
- Summary statistics

---

# Current Status

| Module | Status |
|---------|--------|
| Process Monitor | ✅ Complete |
| File Monitor | ✅ Complete |
| Memory Monitor | ✅ Complete |
| Network Monitor | ✅ Complete |
| save LOGS  | 🚧 In Progress |
| HTML Report | ✅ Working |
| CSS Styling | ✅ Working |

---

# Build

```bash
make
```

---

# Usage

The project includes a sample target program built from:

```text
src/test.c
```

Build and run the monitor with:

```bash
make
make run
```

The `run` target will automatically:

1. Build the Linux System Call Monitor.
2. Build the sample target (`basic_target`).
3. Execute the monitor against the sample target.

If you want to monitor your own program, replace the source file specified by the `TARGET` variable in the `Makefile`:

```make
TARGET = src/test.c
```

For example:

```make
TARGET = src/my_program.c
```

Then rebuild and run:

```bash
make clean
make
make run
```

---

After execution, the following files will be generated:

```text
report.html   -> HTML report containing monitored system calls
alert.txt     -> Security alerts generated during execution
```

Open `report.html` in your browser to inspect the execution report.

---

# Project Structure

```text

```text
.
├── include/
│   ├── alert.h
│   ├── fd_tables.h
│   ├── file_monitor.h
│   ├── memory.h
│   ├── memory_monitor.h
│   ├── network_monitor.h
│   ├── process_monitor.h
│   ├── report.h
│   ├── syscall.h
│   └── tracer.h
│
├── src/
│   ├── main.c
│   ├── tracer.c
│   ├── syscall.c
│   ├── memory.c
│   ├── fd_tables.c
│   ├── file_monitor.c
│   ├── process_monitor.c
│   ├── memory_monitor.c
│   ├── network_monitor.c
│   ├── alert.c
│   ├── report.c
│   └── test.c
│
├── alert.txt          # Runtime security alerts
├── report.html        # Generated after execution
├── style.css
├── Makefile
└── README.md
```



---

# Disclaimer

This project is intended **only for educational and research purposes**.

It demonstrates Linux process tracing through the **ptrace** interface.

Use this software only on processes that you own or have permission to inspect.

The author is **not responsible** for misuse, data loss, or legal consequences resulting from the use of this software.

---

# License

This project is released under the **MIT License**.

---

<p align="center">

Made with ❤️ in C on Linux.

</p>
