package freebsd

var SysNames = map[uint64]string{
	SYS_EXIT:                     "exit",
	SYS_FORK:                     "fork",
	SYS_READ:                     "read",
	SYS_WRITE:                    "write",
	SYS_OPEN:                     "open",
	SYS_CLOSE:                    "close",
	SYS_WAIT4:                    "wait4",
	SYS_LINK:                     "link",
	SYS_UNLINK:                   "unlink",
	SYS_CHDIR:                    "chdir",
	SYS_FCHDIR:                   "fchdir",
	SYS_CHMOD:                    "chmod",
	SYS_CHOWN:                    "chown",
	SYS_BREAK:                    "break",
	SYS_GETPID:                   "getpid",
	SYS_MOUNT:                    "mount",
	SYS_UNMOUNT:                  "unmount",
	SYS_SETUID:                   "setuid",
	SYS_GETUID:                   "getuid",
	SYS_GETEUID:                  "geteuid",
	SYS_PTRACE:                   "ptrace",
	SYS_RECVMSG:                  "recvmsg",
	SYS_SENDMSG:                  "sendmsg",
	SYS_RECVFROM:                 "recvfrom",
	SYS_ACCEPT:                   "accept",
	SYS_GETPEERNAME:              "getpeername",
	SYS_GETSOCKNAME:              "getsockname",
	SYS_ACCESS:                   "access",
	SYS_CHFLAGS:                  "chflags",
	SYS_FCHFLAGS:                 "fchflags",
	SYS_SYNC:                     "sync",
	SYS_KILL:                     "kill",
	SYS_GETPPID:                  "getppid",
	SYS_DUP:                      "dup",
	SYS_GETEGID:                  "getegid",
	SYS_PROFIL:                   "profil",
	SYS_KTRACE:                   "ktrace",
	SYS_GETGID:                   "getgid",
	SYS_GETLOGIN:                 "getlogin",
	SYS_SETLOGIN:                 "setlogin",
	SYS_ACCT:                     "acct",
	SYS_SIGALTSTACK:              "sigaltstack",
	SYS_IOCTL:                    "ioctl",
	SYS_REBOOT:                   "reboot",
	SYS_REVOKE:                   "revoke",
	SYS_SYMLINK:                  "symlink",
	SYS_READLINK:                 "readlink",
	SYS_EXECVE:                   "execve",
	SYS_UMASK:                    "umask",
	SYS_CHROOT:                   "chroot",
	SYS_MSYNC:                    "msync",
	SYS_VFORK:                    "vfork",
	SYS_SBRK:                     "sbrk",
	SYS_SSTK:                     "sstk",
	SYS_MUNMAP:                   "munmap",
	SYS_MPROTECT:                 "mprotect",
	SYS_MADVISE:                  "madvise",
	SYS_MINCORE:                  "mincore",
	SYS_GETGROUPS:                "getgroups",
	SYS_SETGROUPS:                "setgroups",
	SYS_GETPGRP:                  "getpgrp",
	SYS_SETPGID:                  "setpgid",
	SYS_SETITIMER:                "setitimer",
	SYS_SWAPON:                   "swapon",
	SYS_GETITIMER:                "getitimer",
	SYS_GETDTABLESIZE:            "getdtablesize",
	SYS_DUP2:                     "dup2",
	SYS_FCNTL:                    "fcntl",
	SYS_SELECT:                   "select",
	SYS_FSYNC:                    "fsync",
	SYS_SETPRIORITY:              "setpriority",
	SYS_SOCKET:                   "socket",
	SYS_CONNECT:                  "connect",
	SYS_GETPRIORITY:              "getpriority",
	SYS_BIND:                     "bind",
	SYS_SETSOCKOPT:               "setsockopt",
	SYS_LISTEN:                   "listen",
	SYS_GETTIMEOFDAY:             "gettimeofday",
	SYS_GETRUSAGE:                "getrusage",
	SYS_GETSOCKOPT:               "getsockopt",
	SYS_READV:                    "readv",
	SYS_WRITEV:                   "writev",
	SYS_SETTIMEOFDAY:             "settimeofday",
	SYS_FCHOWN:                   "fchown",
	SYS_FCHMOD:                   "fchmod",
	SYS_SETREUID:                 "setreuid",
	SYS_SETREGID:                 "setregid",
	SYS_RENAME:                   "rename",
	SYS_FLOCK:                    "flock",
	SYS_MKFIFO:                   "mkfifo",
	SYS_SENDTO:                   "sendto",
	SYS_SHUTDOWN:                 "shutdown",
	SYS_SOCKETPAIR:               "socketpair",
	SYS_MKDIR:                    "mkdir",
	SYS_RMDIR:                    "rmdir",
	SYS_UTIMES:                   "utimes",
	SYS_ADJTIME:                  "adjtime",
	SYS_SETSID:                   "setsid",
	SYS_QUOTACTL:                 "quotactl",
	SYS_NLM_SYSCALL:              "nlm_syscall",
	SYS_NFSSVC:                   "nfssvc",
	SYS_LGETFH:                   "lgetfh",
	SYS_GETFH:                    "getfh",
	SYS_SYSARCH:                  "sysarch",
	SYS_RTPRIO:                   "rtprio",
	SYS_SEMSYS:                   "semsys",
	SYS_MSGSYS:                   "msgsys",
	SYS_SHMSYS:                   "shmsys",
	SYS_SETFIB:                   "setfib",
	SYS_NTP_ADJTIME:              "ntp_adjtime",
	SYS_SETGID:                   "setgid",
	SYS_SETEGID:                  "setegid",
	SYS_SETEUID:                  "seteuid",
	SYS_PATHCONF:                 "pathconf",
	SYS_FPATHCONF:                "fpathconf",
	SYS_GETRLIMIT:                "getrlimit",
	SYS_SETRLIMIT:                "setrlimit",
	SYS___SYSCTL:                 "__sysctl",
	SYS_MLOCK:                    "mlock",
	SYS_MUNLOCK:                  "munlock",
	SYS_UNDELETE:                 "undelete",
	SYS_FUTIMES:                  "futimes",
	SYS_GETPGID:                  "getpgid",
	SYS_POLL:                     "poll",
	SYS_SEMGET:                   "semget",
	SYS_SEMOP:                    "semop",
	SYS_MSGGET:                   "msgget",
	SYS_MSGSND:                   "msgsnd",
	SYS_MSGRCV:                   "msgrcv",
	SYS_SHMAT:                    "shmat",
	SYS_SHMDT:                    "shmdt",
	SYS_SHMGET:                   "shmget",
	SYS_CLOCK_GETTIME:            "clock_gettime",
	SYS_CLOCK_SETTIME:            "clock_settime",
	SYS_CLOCK_GETRES:             "clock_getres",
	SYS_KTIMER_CREATE:            "ktimer_create",
	SYS_KTIMER_DELETE:            "ktimer_delete",
	SYS_KTIMER_SETTIME:           "ktimer_settime",
	SYS_KTIMER_GETTIME:           "ktimer_gettime",
	SYS_KTIMER_GETOVERRUN:        "ktimer_getoverrun",
	SYS_NANOSLEEP:                "nanosleep",
	SYS_FFCLOCK_GETCOUNTER:       "ffclock_getcounter",
	SYS_FFCLOCK_SETESTIMATE:      "ffclock_setestimate",
	SYS_FFCLOCK_GETESTIMATE:      "ffclock_getestimate",
	SYS_CLOCK_NANOSLEEP:          "clock_nanosleep",
	SYS_CLOCK_GETCPUCLOCKID2:     "clock_getcpuclockid2",
	SYS_NTP_GETTIME:              "ntp_gettime",
	SYS_MINHERIT:                 "minherit",
	SYS_RFORK:                    "rfork",
	SYS_ISSETUGID:                "issetugid",
	SYS_LCHOWN:                   "lchown",
	SYS_AIO_READ:                 "aio_read",
	SYS_AIO_WRITE:                "aio_write",
	SYS_LIO_LISTIO:               "lio_listio",
	SYS_LCHMOD:                   "lchmod",
	SYS_LUTIMES:                  "lutimes",
	SYS_PREADV:                   "preadv",
	SYS_PWRITEV:                  "pwritev",
	SYS_FHOPEN:                   "fhopen",
	SYS_MODNEXT:                  "modnext",
	SYS_MODSTAT:                  "modstat",
	SYS_MODFNEXT:                 "modfnext",
	SYS_MODFIND:                  "modfind",
	SYS_KLDLOAD:                  "kldload",
	SYS_KLDUNLOAD:                "kldunload",
	SYS_KLDFIND:                  "kldfind",
	SYS_KLDNEXT:                  "kldnext",
	SYS_KLDSTAT:                  "kldstat",
	SYS_KLDFIRSTMOD:              "kldfirstmod",
	SYS_GETSID:                   "getsid",
	SYS_SETRESUID:                "setresuid",
	SYS_SETRESGID:                "setresgid",
	SYS_AIO_RETURN:               "aio_return",
	SYS_AIO_SUSPEND:              "aio_suspend",
	SYS_AIO_CANCEL:               "aio_cancel",
	SYS_AIO_ERROR:                "aio_error",
	SYS_YIELD:                    "yield",
	SYS_MLOCKALL:                 "mlockall",
	SYS_MUNLOCKALL:               "munlockall",
	SYS___GETCWD:                 "__getcwd",
	SYS_SCHED_SETPARAM:           "sched_setparam",
	SYS_SCHED_GETPARAM:           "sched_getparam",
	SYS_SCHED_SETSCHEDULER:       "sched_setscheduler",
	SYS_SCHED_GETSCHEDULER:       "sched_getscheduler",
	SYS_SCHED_YIELD:              "sched_yield",
	SYS_SCHED_GET_PRIORITY_MAX:   "sched_get_priority_max",
	SYS_SCHED_GET_PRIORITY_MIN:   "sched_get_priority_min",
	SYS_SCHED_RR_GET_INTERVAL:    "sched_rr_get_interval",
	SYS_UTRACE:                   "utrace",
	SYS_KLDSYM:                   "kldsym",
	SYS_JAIL:                     "jail",
	SYS_SIGPROCMASK:              "sigprocmask",
	SYS_SIGSUSPEND:               "sigsuspend",
	SYS_SIGPENDING:               "sigpending",
	SYS_SIGTIMEDWAIT:             "sigtimedwait",
	SYS_SIGWAITINFO:              "sigwaitinfo",
	SYS___ACL_GET_FILE:           "__acl_get_file",
	SYS___ACL_SET_FILE:           "__acl_set_file",
	SYS___ACL_GET_FD:             "__acl_get_fd",
	SYS___ACL_SET_FD:             "__acl_set_fd",
	SYS___ACL_DELETE_FILE:        "__acl_delete_file",
	SYS___ACL_DELETE_FD:          "__acl_delete_fd",
	SYS___ACL_ACLCHECK_FILE:      "__acl_aclcheck_file",
	SYS___ACL_ACLCHECK_FD:        "__acl_aclcheck_fd",
	SYS_EXTATTRCTL:               "extattrctl",
	SYS_EXTATTR_SET_FILE:         "extattr_set_file",
	SYS_EXTATTR_GET_FILE:         "extattr_get_file",
	SYS_EXTATTR_DELETE_FILE:      "extattr_delete_file",
	SYS_AIO_WAITCOMPLETE:         "aio_waitcomplete",
	SYS_GETRESUID:                "getresuid",
	SYS_GETRESGID:                "getresgid",
	SYS_KQUEUE:                   "kqueue",
	SYS_EXTATTR_SET_FD:           "extattr_set_fd",
	SYS_EXTATTR_GET_FD:           "extattr_get_fd",
	SYS_EXTATTR_DELETE_FD:        "extattr_delete_fd",
	SYS___SETUGID:                "__setugid",
	SYS_EACCESS:                  "eaccess",
	SYS_NMOUNT:                   "nmount",
	SYS___MAC_GET_PROC:           "__mac_get_proc",
	SYS___MAC_SET_PROC:           "__mac_set_proc",
	SYS___MAC_GET_FD:             "__mac_get_fd",
	SYS___MAC_GET_FILE:           "__mac_get_file",
	SYS___MAC_SET_FD:             "__mac_set_fd",
	SYS___MAC_SET_FILE:           "__mac_set_file",
	SYS_KENV:                     "kenv",
	SYS_LCHFLAGS:                 "lchflags",
	SYS_UUIDGEN:                  "uuidgen",
	SYS_SENDFILE:                 "sendfile",
	SYS_MAC_SYSCALL:              "mac_syscall",
	SYS_KSEM_CLOSE:               "ksem_close",
	SYS_KSEM_POST:                "ksem_post",
	SYS_KSEM_WAIT:                "ksem_wait",
	SYS_KSEM_TRYWAIT:             "ksem_trywait",
	SYS_KSEM_INIT:                "ksem_init",
	SYS_KSEM_OPEN:                "ksem_open",
	SYS_KSEM_UNLINK:              "ksem_unlink",
	SYS_KSEM_GETVALUE:            "ksem_getvalue",
	SYS_KSEM_DESTROY:             "ksem_destroy",
	SYS___MAC_GET_PID:            "__mac_get_pid",
	SYS___MAC_GET_LINK:           "__mac_get_link",
	SYS___MAC_SET_LINK:           "__mac_set_link",
	SYS_EXTATTR_SET_LINK:         "extattr_set_link",
	SYS_EXTATTR_GET_LINK:         "extattr_get_link",
	SYS_EXTATTR_DELETE_LINK:      "extattr_delete_link",
	SYS___MAC_EXECVE:             "__mac_execve",
	SYS_SIGACTION:                "sigaction",
	SYS_SIGRETURN:                "sigreturn",
	SYS_GETCONTEXT:               "getcontext",
	SYS_SETCONTEXT:               "setcontext",
	SYS_SWAPCONTEXT:              "swapcontext",
	SYS_SWAPOFF:                  "swapoff",
	SYS___ACL_GET_LINK:           "__acl_get_link",
	SYS___ACL_SET_LINK:           "__acl_set_link",
	SYS___ACL_DELETE_LINK:        "__acl_delete_link",
	SYS___ACL_ACLCHECK_LINK:      "__acl_aclcheck_link",
	SYS_SIGWAIT:                  "sigwait",
	SYS_THR_CREATE:               "thr_create",
	SYS_THR_EXIT:                 "thr_exit",
	SYS_THR_SELF:                 "thr_self",
	SYS_THR_KILL:                 "thr_kill",
	SYS_JAIL_ATTACH:              "jail_attach",
	SYS_EXTATTR_LIST_FD:          "extattr_list_fd",
	SYS_EXTATTR_LIST_FILE:        "extattr_list_file",
	SYS_EXTATTR_LIST_LINK:        "extattr_list_link",
	SYS_KSEM_TIMEDWAIT:           "ksem_timedwait",
	SYS_THR_SUSPEND:              "thr_suspend",
	SYS_THR_WAKE:                 "thr_wake",
	SYS_KLDUNLOADF:               "kldunloadf",
	SYS_AUDIT:                    "audit",
	SYS_AUDITON:                  "auditon",
	SYS_GETAUID:                  "getauid",
	SYS_SETAUID:                  "setauid",
	SYS_GETAUDIT:                 "getaudit",
	SYS_SETAUDIT:                 "setaudit",
	SYS_GETAUDIT_ADDR:            "getaudit_addr",
	SYS_SETAUDIT_ADDR:            "setaudit_addr",
	SYS_AUDITCTL:                 "auditctl",
	SYS__UMTX_OP:                 "_umtx_op",
	SYS_THR_NEW:                  "thr_new",
	SYS_SIGQUEUE:                 "sigqueue",
	SYS_KMQ_OPEN:                 "kmq_open",
	SYS_KMQ_SETATTR:              "kmq_setattr",
	SYS_KMQ_TIMEDRECEIVE:         "kmq_timedreceive",
	SYS_KMQ_TIMEDSEND:            "kmq_timedsend",
	SYS_KMQ_NOTIFY:               "kmq_notify",
	SYS_KMQ_UNLINK:               "kmq_unlink",
	SYS_ABORT2:                   "abort2",
	SYS_THR_SET_NAME:             "thr_set_name",
	SYS_AIO_FSYNC:                "aio_fsync",
	SYS_RTPRIO_THREAD:            "rtprio_thread",
	SYS_SCTP_PEELOFF:             "sctp_peeloff",
	SYS_SCTP_GENERIC_SENDMSG:     "sctp_generic_sendmsg",
	SYS_SCTP_GENERIC_SENDMSG_IOV: "sctp_generic_sendmsg_iov",
	SYS_SCTP_GENERIC_RECVMSG:     "sctp_generic_recvmsg",
	SYS_PREAD:                    "pread",
	SYS_PWRITE:                   "pwrite",
	SYS_MMAP:                     "mmap",
	SYS_LSEEK:                    "lseek",
	SYS_TRUNCATE:                 "truncate",
	SYS_FTRUNCATE:                "ftruncate",
	SYS_THR_KILL2:                "thr_kill2",
	SYS_SHM_OPEN:                 "shm_open",
	SYS_SHM_UNLINK:               "shm_unlink",
	SYS_CPUSET:                   "cpuset",
	SYS_CPUSET_SETID:             "cpuset_setid",
	SYS_CPUSET_GETID:             "cpuset_getid",
	SYS_CPUSET_GETAFFINITY:       "cpuset_getaffinity",
	SYS_CPUSET_SETAFFINITY:       "cpuset_setaffinity",
	SYS_FACCESSAT:                "faccessat",
	SYS_FCHMODAT:                 "fchmodat",
	SYS_FCHOWNAT:                 "fchownat",
	SYS_FEXECVE:                  "fexecve",
	SYS_FUTIMESAT:                "futimesat",
	SYS_LINKAT:                   "linkat",
	SYS_MKDIRAT:                  "mkdirat",
	SYS_MKFIFOAT:                 "mkfifoat",
	SYS_OPENAT:                   "openat",
	SYS_READLINKAT:               "readlinkat",
	SYS_RENAMEAT:                 "renameat",
	SYS_SYMLINKAT:                "symlinkat",
	SYS_UNLINKAT:                 "unlinkat",
	SYS_POSIX_OPENPT:             "posix_openpt",
	SYS_GSSD_SYSCALL:             "gssd_syscall",
	SYS_JAIL_GET:                 "jail_get",
	SYS_JAIL_SET:                 "jail_set",
	SYS_JAIL_REMOVE:              "jail_remove",
	SYS_CLOSEFROM:                "closefrom",
	SYS___SEMCTL:                 "__semctl",
	SYS_MSGCTL:                   "msgctl",
	SYS_SHMCTL:                   "shmctl",
	SYS_LPATHCONF:                "lpathconf",
	SYS___CAP_RIGHTS_GET:         "__cap_rights_get",
	SYS_CAP_ENTER:                "cap_enter",
	SYS_CAP_GETMODE:              "cap_getmode",
	SYS_PDFORK:                   "pdfork",
	SYS_PDKILL:                   "pdkill",
	SYS_PDGETPID:                 "pdgetpid",
	SYS_PSELECT:                  "pselect",
	SYS_GETLOGINCLASS:            "getloginclass",
	SYS_SETLOGINCLASS:            "setloginclass",
	SYS_RCTL_GET_RACCT:           "rctl_get_racct",
	SYS_RCTL_GET_RULES:           "rctl_get_rules",
	SYS_RCTL_GET_LIMITS:          "rctl_get_limits",
	SYS_RCTL_ADD_RULE:            "rctl_add_rule",
	SYS_RCTL_REMOVE_RULE:         "rctl_remove_rule",
	SYS_POSIX_FALLOCATE:          "posix_fallocate",
	SYS_POSIX_FADVISE:            "posix_fadvise",
	SYS_WAIT6:                    "wait6",
	SYS_CAP_RIGHTS_LIMIT:         "cap_rights_limit",
	SYS_CAP_IOCTLS_LIMIT:         "cap_ioctls_limit",
	SYS_CAP_IOCTLS_GET:           "cap_ioctls_get",
	SYS_CAP_FCNTLS_LIMIT:         "cap_fcntls_limit",
	SYS_CAP_FCNTLS_GET:           "cap_fcntls_get",
	SYS_BINDAT:                   "bindat",
	SYS_CONNECTAT:                "connectat",
	SYS_CHFLAGSAT:                "chflagsat",
	SYS_ACCEPT4:                  "accept4",
	SYS_PIPE2:                    "pipe2",
	SYS_AIO_MLOCK:                "aio_mlock",
	SYS_PROCCTL:                  "procctl",
	SYS_PPOLL:                    "ppoll",
	SYS_FUTIMENS:                 "futimens",
	SYS_UTIMENSAT:                "utimensat",
	SYS_FDATASYNC:                "fdatasync",
	SYS_FSTAT:                    "fstat",
	SYS_FSTATAT:                  "fstatat",
	SYS_FHSTAT:                   "fhstat",
	SYS_GETDIRENTRIES:            "getdirentries",
	SYS_STATFS:                   "statfs",
	SYS_FSTATFS:                  "fstatfs",
	SYS_GETFSSTAT:                "getfsstat",
	SYS_FHSTATFS:                 "fhstatfs",
	SYS_MKNODAT:                  "mknodat",
	SYS_KEVENT:                   "kevent",
	SYS_CPUSET_GETDOMAIN:         "cpuset_getdomain",
	SYS_CPUSET_SETDOMAIN:         "cpuset_setdomain",
	SYS_GETRANDOM:                "getrandom",
	SYS_GETFHAT:                  "getfhat",
	SYS_FHLINK:                   "fhlink",
	SYS_FHLINKAT:                 "fhlinkat",
	SYS_FHREADLINK:               "fhreadlink",
	SYS___SYSCTLBYNAME:           "__sysctlbyname",
	SYS_CLOSE_RANGE:              "close_range",
}