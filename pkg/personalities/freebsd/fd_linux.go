package freebsd

import (
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func openHandler(sc *tracer.SyscallCtx) error {
	//  int open(const char *pathname, int flags, mode_t mode);
	// FIXME: "Linux reserves the special, nonstandard access mode 3 (binary 11)"
	// https://man7.org/linux/man-pages/man2/open.2.html
	if sc.Entry {
		origFlags := sc.Regs.Arg(1)
		flags := openFlagsToFreeBSD(origFlags)
		sc.Regs.SetArg(1, flags)
	}
	return simpleHandler(unix.SYS_OPEN)(sc)
}

func openatHandler(sc *tracer.SyscallCtx) error {
	// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
	if sc.Entry {
		origFlags := sc.Regs.Arg(2)
		flags := openFlagsToFreeBSD(origFlags)
		sc.Regs.SetArg(2, flags)
	}
	return simpleHandler(unix.SYS_OPENAT)(sc)
}

func openFlagsToFreeBSD(origFlags uint64) uint64 {
	var flags uint64
	m := map[uint64]uint64{
		// O_ACCMODE: N/A
		freebsd.O_APPEND:    unix.O_APPEND,
		freebsd.O_ASYNC:     unix.O_ASYNC,
		freebsd.O_CLOEXEC:   unix.O_CLOEXEC,
		freebsd.O_CREAT:     unix.O_CREAT,
		freebsd.O_DIRECT:    unix.O_DIRECT,
		freebsd.O_DIRECTORY: unix.O_DIRECTORY,
		freebsd.O_EXCL:      unix.O_EXCL,
		// O_EXEC: N/A
		// O_EXLOCK: N/A
		freebsd.O_FSYNC:    unix.O_FSYNC,
		freebsd.O_NDELAY:   unix.O_NDELAY,
		freebsd.O_NOCTTY:   unix.O_NOCTTY,
		freebsd.O_NOFOLLOW: unix.O_NOFOLLOW,
		// O_NONBLOCK: an alias of O_NDELAY
		freebsd.O_RDONLY: unix.O_RDONLY,
		freebsd.O_RDWR:   unix.O_RDWR,
		// O_RESOLVE_BENEATH: N/A
		// O_SEARCH: N/A
		// O_SHLOCK: N/A
		// O_SYNC: an alias of O_FSYNC
		freebsd.O_TRUNC: unix.O_TRUNC,
		// O_TTY_INIT: N/A
		// O_VERIFY: N/A
		freebsd.O_WRONLY: unix.O_WRONLY,
	}
	for k, v := range m {
		if origFlags&k != 0 {
			flags |= v
			origFlags &= ^k
		}
	}
	if origFlags&freebsd.O_VERIFY != 0 {
		logrus.Debugf("SYS_OPEN*: ignoring O_VERIFY")
		origFlags &= ^uint64(freebsd.O_VERIFY)
	}
	if origFlags != 0 {
		logrus.Debugf("SYS_OPEN*: ignoring unsupported flags 0x%x", origFlags)
	}
	return flags
}
