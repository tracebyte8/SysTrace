#include "syscall.h"
#include <sys/syscall.h>

const char *syscall_name(long syscall)
{
    switch (syscall)
    {
        /* File */
        case SYS_read:               return "read";
        case SYS_write:              return "write";
        case SYS_open:               return "open";
        case SYS_openat:             return "openat";
        case SYS_close:              return "close";
        case SYS_lseek:              return "lseek";
        case SYS_stat:               return "stat";
        case SYS_fstat:              return "fstat";
        case SYS_newfstatat:         return "newfstatat";
        case SYS_access:             return "access";

        /* Memory */
        case SYS_mmap:               return "mmap";
        case SYS_mprotect:           return "mprotect";
        case SYS_munmap:             return "munmap";
        case SYS_brk:                return "brk";
        case SYS_madvise:            return "madvise";

        /* Process */
        case SYS_execve:             return "execve";
        case SYS_fork:               return "fork";
        case SYS_vfork:              return "vfork";
        case SYS_clone:              return "clone";
        case SYS_wait4:              return "wait4";
        case SYS_exit:               return "exit";
        case SYS_exit_group:         return "exit_group";

        /* Signals */
        case SYS_rt_sigaction:       return "rt_sigaction";
        case SYS_rt_sigprocmask:     return "rt_sigprocmask";
        case SYS_rt_sigreturn:       return "rt_sigreturn";

        /* Threads */
        case SYS_set_tid_address:    return "set_tid_address";
        case SYS_set_robust_list:    return "set_robust_list";
        case SYS_rseq:               return "rseq";
        case SYS_futex:              return "futex";
        case SYS_gettid:             return "gettid";
        case SYS_getpid:             return "getpid";

        /* Architecture */
        case SYS_arch_prctl:         return "arch_prctl";

        /* Random / limits */
        case SYS_getrandom:          return "getrandom";
        case SYS_prlimit64:          return "prlimit64";

        /* Others */
        case SYS_ioctl:              return "ioctl";
        case SYS_pread64:            return "pread64";
        case SYS_writev:             return "writev";

        default:
            return "unknown";
    }
}