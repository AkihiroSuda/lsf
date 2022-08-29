package freebsd

import (
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func wait4Handler(sc *tracer.SyscallCtx) error {
	// pid_t wait4(pid_t wpid, int *status, int options, struct	rusage *rusage);
	if sc.Entry {
		origFlags := sc.Regs.Arg(2)
		flags := waitOptionFlagsToLinux(origFlags)
		sc.Regs.SetArg(2, flags)
	}
	return simpleHandler(unix.SYS_WAIT4)(sc)
}

func waitOptionFlagsToLinux(origFlags uint64) uint64 {
	var flags uint64
	m := map[uint64]uint64{
		freebsd.WCONTINUED: unix.WCONTINUED,
		freebsd.WNOHANG:    unix.WNOHANG,
		freebsd.WUNTRACED:  unix.WUNTRACED,
		// WSTOPPED: an alias of WUNTRACED
		// WTRAPPED: N/A
		freebsd.WEXITED: unix.WEXITED,
		freebsd.WNOWAIT: unix.WNOWAIT,
	}
	for k, v := range m {
		if origFlags&k != 0 {
			flags |= v
			origFlags &= ^k
		}
	}
	if origFlags != 0 {
		logrus.Debugf("SYS_WAIT*: ignoring unsupported flags 0x%x", origFlags)
	}
	return flags
}
