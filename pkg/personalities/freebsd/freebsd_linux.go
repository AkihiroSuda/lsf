package freebsd

import (
	"fmt"
	"math/rand"
	"time"

	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	KernOSRelDate = 1301000                         // kern.osreldate
	KernOSRelease = "13.1-RELEASE-p1"               // kern.osrelease
	KernVersion   = "FreeBSD 13.1-RELEASE-p1 LSF\n" // kern.version (with "\n")
)

func New() tracer.Personality {
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &personality{
		rand: rand,
	}
}

type personality struct {
	rand rand.Source
}

func (p *personality) HandleSyscall(sc *tracer.SyscallCtx) error {
	if sc.Entry {
		logrus.Debugf("PID %08d ENTER                     syscall %d %s (0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)",
			sc.Pid, sc.Num, freebsd.SysNames[sc.Num], sc.Regs.Arg(0), sc.Regs.Arg(1), sc.Regs.Arg(2), sc.Regs.Arg(3), sc.Regs.Arg(4), sc.Regs.Arg(5))
	}
	handler, ok := syscallHandlers[sc.Num]
	if !ok {
		logrus.Debugf("Unimplemented syscall %d %s", sc.Num, freebsd.SysNames[sc.Num])
		handler = defaultHandler
	}
	if err := handler(sc); err != nil {
		return fmt.Errorf("failed to call the handler for syscall %d %s (entry=%v): %w",
			sc.Num, freebsd.SysNames[sc.Num], sc.Entry, err)
	}
	if !sc.Entry {
		logrus.Debugf("PID %08d RETURN 0x%016x syscall %d %s (0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)",
			sc.Pid, sc.Regs.Ret(), sc.Num, freebsd.SysNames[sc.Num], sc.Regs.Arg(0), sc.Regs.Arg(1), sc.Regs.Arg(2), sc.Regs.Arg(3), sc.Regs.Arg(4), sc.Regs.Arg(5))
	}
	return nil
}

const nopSyscall = unix.SYS_GETPID

func stubHandler(errno freebsd.Errno, comments ...string) tracer.SyscallHandler {
	return func(sc *tracer.SyscallCtx) error {
		if sc.Entry {
			logrus.Debugf("Stub syscall %d %s (errno %d) %v", sc.Num, freebsd.SysNames[sc.Num], errno, comments)
			sc.Regs.SetSyscall(nopSyscall)
		} else {
			ret := -1 * int(errno)
			sc.Regs.SetRet(uint64(ret))
		}
		return nil
	}
}

var defaultHandler tracer.SyscallHandler = stubHandler(freebsd.ENOSYS)

func simpleHandler(native uint64) tracer.SyscallHandler {
	return func(sc *tracer.SyscallCtx) error {
		if sc.Entry {
			sc.Regs.SetSyscall(native)
		} else {
			sc.Regs.AdjustRet() // FIXME: convert errno
		}
		return nil
	}
}

var syscallHandlers = map[uint64]tracer.SyscallHandler{
	0: func(sc *tracer.SyscallCtx) error {
		// e.g, 0xbd == 189 == freebsd11 freebsd32_fstat
		return stubHandler(freebsd.ENOSYS, fmt.Sprintf("Unexpected 32-bit call 0x%x?, PC=0x%x, regs=%+v",
			sc.Regs.Arg(0), sc.Regs.PC(), sc.Regs))(sc)
	},
	freebsd.SYS_EXIT:   simpleHandler(unix.SYS_EXIT),
	freebsd.SYS_FORK:   simpleHandler(unix.SYS_FORK),
	freebsd.SYS_READ:   simpleHandler(unix.SYS_READ),
	freebsd.SYS_WRITE:  simpleHandler(unix.SYS_WRITE),
	freebsd.SYS_OPEN:   openHandler,
	freebsd.SYS_CLOSE:  simpleHandler(unix.SYS_CLOSE),
	freebsd.SYS_WAIT4:  wait4Handler,
	freebsd.SYS_LINK:   simpleHandler(unix.SYS_LINK),
	freebsd.SYS_UNLINK: simpleHandler(unix.SYS_UNLINK),
	freebsd.SYS_CHDIR:  simpleHandler(unix.SYS_CHDIR),
	freebsd.SYS_FCHDIR: simpleHandler(unix.SYS_FCHDIR),
	freebsd.SYS_CHMOD:  simpleHandler(unix.SYS_CHMOD),
	freebsd.SYS_CHOWN:  simpleHandler(unix.SYS_CHOWN),
	// SYS_BREAK: N/A
	freebsd.SYS_GETPID: simpleHandler(unix.SYS_GETPID),
	// SYS_MOUNT: TODO
	// SYS_UNMOUNT: TODO
	freebsd.SYS_SETUID:  simpleHandler(unix.SYS_SETUID),
	freebsd.SYS_GETUID:  simpleHandler(unix.SYS_GETUID),
	freebsd.SYS_GETEUID: simpleHandler(unix.SYS_GETEUID),
	// SYS_PTRACE: TODO (Never?)
	// SYS_RECVMSG: TODO
	// SYS_SENDMSG: TODO
	// ...
	freebsd.SYS_SYNC:    simpleHandler(unix.SYS_SYNC),
	freebsd.SYS_KILL:    simpleHandler(unix.SYS_KILL),
	freebsd.SYS_GETPPID: simpleHandler(unix.SYS_GETPPID),
	freebsd.SYS_DUP:     simpleHandler(unix.SYS_DUP),
	freebsd.SYS_GETEGID: simpleHandler(unix.SYS_GETEGID),
	// SYS_PROFIL: N/A
	// SYS_KTRACE: N/A
	freebsd.SYS_GETGID: simpleHandler(unix.SYS_GETGID),
	// SYS_GETLOGIN: N/A
	// SYS_SETLOGIN: N/A
	freebsd.SYS_ACCT: simpleHandler(unix.SYS_ACCT),
	// SYS_SIGALTSTACK: TODO
	freebsd.SYS_IOCTL:  stubHandler(0),
	freebsd.SYS_REBOOT: stubHandler(freebsd.ENOTSUP),
	// SYS_REVOKE: N/A
	freebsd.SYS_SYMLINK:  simpleHandler(unix.SYS_SYMLINK),
	freebsd.SYS_READLINK: simpleHandler(unix.SYS_READLINK),
	freebsd.SYS_EXECVE:   simpleHandler(unix.SYS_EXECVE),
	freebsd.SYS_UMASK:    simpleHandler(unix.SYS_UMASK),
	freebsd.SYS_CHROOT:   simpleHandler(unix.SYS_CHROOT),
	// SYS_MSYNC: TODO
	// SYS_VFORK: TODO
	// SYS_SBRK: TODO (using SYS_BRK)
	// SYS_SSTK: N/A
	freebsd.SYS_MUNMAP:    simpleHandler(unix.SYS_MUNMAP),
	freebsd.SYS_MPROTECT:  simpleHandler(unix.SYS_MPROTECT),
	freebsd.SYS_MADVISE:   simpleHandler(unix.SYS_MADVISE),
	freebsd.SYS_GETGROUPS: simpleHandler(unix.SYS_GETGROUPS),
	freebsd.SYS_SETGROUPS: simpleHandler(unix.SYS_SETGROUPS),
	freebsd.SYS_GETPGRP:   simpleHandler(unix.SYS_GETPGRP),
	freebsd.SYS_GETPGID:   simpleHandler(unix.SYS_GETPGID),
	freebsd.SYS_DUP2:      simpleHandler(freebsd.SYS_DUP2),
	freebsd.SYS_FSYNC:     simpleHandler(unix.SYS_FSYNC),
	//================================================== 100 ==================================================
	freebsd.SYS_GETPRIORITY:  simpleHandler(unix.SYS_GETPRIORITY),
	freebsd.SYS_LISTEN:       simpleHandler(unix.SYS_LISTEN),
	freebsd.SYS_GETTIMEOFDAY: simpleHandler(unix.SYS_GETTIMEOFDAY),
	freebsd.SYS_READV:        simpleHandler(unix.SYS_READV),
	freebsd.SYS_WRITEV:       simpleHandler(unix.SYS_WRITEV),
	freebsd.SYS_SETTIMEOFDAY: simpleHandler(unix.SYS_SETTIMEOFDAY),
	freebsd.SYS_FCHOWN:       simpleHandler(unix.SYS_FCHOWN),
	freebsd.SYS_FCHMOD:       simpleHandler(unix.SYS_FCHMOD),
	freebsd.SYS_SETREUID:     simpleHandler(unix.SYS_SETREUID),
	freebsd.SYS_SETREGID:     simpleHandler(unix.SYS_SETREGID),
	freebsd.SYS_RENAME:       simpleHandler(unix.SYS_RENAME),
	// SYS_MKFIFO: N/A
	freebsd.SYS_MKDIR:  simpleHandler(unix.SYS_MKDIR),
	freebsd.SYS_RMDIR:  simpleHandler(unix.SYS_RMDIR),
	freebsd.SYS_UTIMES: simpleHandler(unix.SYS_UTIMES),
	// SYS_ADJTIME: N/A
	freebsd.SYS_SETSID:  simpleHandler(unix.SYS_SETSID),
	freebsd.SYS_SYSARCH: sysarchHandler,
	// SYS_SETE{U,G}ID: N/A
	//================================================== 200 ==================================================
	freebsd.SYS___SYSCTL:      sysctlHandler,
	freebsd.SYS_CLOCK_GETTIME: simpleHandler(unix.SYS_CLOCK_GETTIME),
	freebsd.SYS_CLOCK_SETTIME: simpleHandler(unix.SYS_CLOCK_SETTIME),
	freebsd.SYS_NANOSLEEP:     simpleHandler(unix.SYS_NANOSLEEP),
	freebsd.SYS_ISSETUGID:     stubHandler(0),
	freebsd.SYS_LCHOWN:        simpleHandler(unix.SYS_LCHOWN),
	// SYS_LUTIMES: N/A
	freebsd.SYS_PREADV:  simpleHandler(unix.SYS_PREADV),
	freebsd.SYS_PWRITEV: simpleHandler(unix.SYS_PWRITEV),
	// SYS_FHOPEN: N/A

	//================================================== 300 ==================================================
	freebsd.SYS_GETSID: simpleHandler(unix.SYS_GETSID),

	freebsd.SYS_SIGPROCMASK: func(sc *tracer.SyscallCtx) error {
		if sc.Entry {
			// sigsetsize is 16 bytes: https://github.com/golang/sys/blob/2296e01440c6f831795fdeb206cb9da8d562444e/unix/ztypes_freebsd_amd64.go#L314
			sc.Regs.SetArg(3, 16)
		}
		return simpleHandler(unix.SYS_RT_SIGPROCMASK)(sc)
	},
	// SYS_SIGSUSPEND: TODO
	// SYS_SIGPENDING: TODO
	// SYS_SIGTIMEDWAIT: TODO
	// SYS_SIGWAITINFO: TODO
	// SYS___ACL_*: N/A
	// SYS_EXTATTR_{SET,GET,DELETE}_FILE: N/A
	// SYS_AIO_WAITCOMPLETE: N/A
	freebsd.SYS_GETRESUID: simpleHandler(unix.SYS_GETRESUID),
	freebsd.SYS_GETRESGID: simpleHandler(unix.SYS_GETRESGID),
	// SYS_KQUEUE: N/A
	// SYS_EXTATTR_{SET,GET,DELETE}_FD: N/A
	// SYS___SETUGID: N/A
	// SYS_EACCESS: N/A
	// SYS_NMOUNT: N/A
	// SYS___MAC_*: N/A
	// ...
	//================================================== 400 ==================================================
	freebsd.SYS_SIGACTION: simpleHandler(unix.SYS_RT_SIGACTION), // FIXME: probably wrong
	// SYS_THR_CREATE: N/A
	// SYS_THR_EXIT: N/A
	freebsd.SYS_THR_SELF: thrSelfHandler,
	freebsd.SYS_THR_KILL: thrKillHandler,
	// JAIL_ATTACH: N/A
	freebsd.SYS_PREAD:     simpleHandler(unix.SYS_PREAD64),
	freebsd.SYS_PWRITE:    simpleHandler(unix.SYS_PWRITE64),
	freebsd.SYS_MMAP:      mmapHandler,
	freebsd.SYS_LSEEK:     simpleHandler(unix.SYS_LSEEK),
	freebsd.SYS_TRUNCATE:  simpleHandler(unix.SYS_TRUNCATE),
	freebsd.SYS_FTRUNCATE: simpleHandler(unix.SYS_FTRUNCATE),
	freebsd.SYS_OPENAT:    openatHandler,
	//================================================== 500 ==================================================
	freebsd.SYS_READLINKAT:    simpleHandler(unix.SYS_READLINKAT),
	freebsd.SYS_RENAMEAT:      simpleHandler(unix.SYS_RENAMEAT),
	freebsd.SYS_SYMLINKAT:     simpleHandler(unix.SYS_SYMLINKAT),
	freebsd.SYS_UNLINKAT:      simpleHandler(unix.SYS_UNLINKAT),
	freebsd.SYS_FSTAT:         fstatHandler,
	freebsd.SYS_FSTATAT:       fstatatHandler,
	freebsd.SYS_GETDIRENTRIES: getdirentriesHandler,
}
