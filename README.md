# Linux System Call Monitor

<p align="center">

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![ptrace](https://img.shields.io/badge/ptrace-System%20Calls-blue?style=for-the-badge)
![MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</p>

A lightweight **Linux System Call Monitor** written in **C** using the **ptrace** API.

It traces Linux processes, monitors system calls, generates an HTML report, and detects suspicious behaviors through a rule-based detection engine. and save the logs in log.txt , and the high alerts in  alert.json .

the project is under development , he needs some features and getting clean .

---

## Features

- Process tracing with `ptrace`
- File activity monitoring
- Process monitoring (`fork`, `execve`, ...)
- Memory monitoring (`mmap`, `mprotect`, ...)
- Network monitoring (`connect`, `socket`, ...)
- HTML report generation
- Rule-based malware detection
- Alert logging
- Save high Alerts in json file 
- Process blocking (`SIGKILL`) for critical events

---

| Category | Syscalls |
|----------|----------|
| File | `open`, `openat`, `read`, `write`, `close` |
| Process | `fork`, `execve`, `waitpid` |
| Memory | `mmap`, `mprotect`, `munmap` |
| Network | `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv` |

---

## HTML Report

![dashboardexmpl](image/dashboardexmpl.png)

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


Generated files:

```
report.html
log.txt
alert.json
syscall_file.txt
```

---

## Project Structure


```text
.
├── dashboard
│   ├── index.c
│   └── style.css
|
├── include/
│   ├── alert.h
│   ├── fd_tables.h
│   ├── file_monitor.h
│   ├── rules.h
│   ├── event.h
│   ├── memory.h
│   ├── memory_monitor.h
│   ├── network_monitor.h
│   ├── process_monitor.h
│   ├── syscall.h
│   └── tracer.h
│
├── src/
│   ├── main.c
│   ├── tracer.c
│   ├── syscall.c
│   ├── memory.c
│   ├── rules.c
│   ├── fd_tables.c
│   ├── file_monitor.c
│   ├── process_monitor.c
│   ├── memory_monitor.c
│   ├── network_monitor.c
│   ├── alert.c
│   └── test.c
│
├── report.html
├── alert.json       
├── log.txt     
├── syscall_file.txt // the output is here     
├── Makefile
└── README.md
=======
```


---



## Roadmap

- [x] ptrace tracer
- [x] File monitor
- [x] Process monitor
- [x] Memory monitor
- [x] Network monitor
- [x] HTML report
- [x] Rule engine 
- [x] Alert system ( in progress.. )
- [x] JSON alert logging 
- [x] Interactive dashboard

---

## Disclaimer

This project is intended only for educational and research purposes.

It demonstrates Linux process tracing through the ptrace interface.

Use this software only on processes that you own or have permission to inspect.

The author is not responsible for misuse, data loss, or legal consequences resulting from the use of this software.

---

## License

This project is released under the **MIT License**.

---

<p align="center">

Made with ❤️ in C on Linux.

</p>
MIT
