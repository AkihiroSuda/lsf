package freebsd

import (
	"encoding/binary"

	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"golang.org/x/sys/unix"
)

func thrSelfHandler(sc *tracer.SyscallCtx) error {
	// FreeBSD: int thr_self(long *id)
	// Linux:   pid_t gettid(void)
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(unix.SYS_GETTID)
	case false:
		linuxTID := sc.Regs.Ret()
		thr := tidToFreeBSD(linuxTID)
		thrB := make([]byte, 8)
		binary.LittleEndian.PutUint64(thrB, thr)
		thrPtr := uintptr(sc.Regs.Arg(0))
		if _, err := unix.PtracePokeData(sc.Pid, thrPtr, thrB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func thrKillHandler(sc *tracer.SyscallCtx) error {
	// FreeBSD: int thr_kill(long id, int sig);
	// Linux:   int kill(pid_t pid, int sig);
	if sc.Entry {
		sc.Regs.SetArg(0, tidFromFreeBSD(sc.Regs.Arg(0)))
	}
	return simpleHandler(unix.SYS_KILL)(sc)
}

// https://www.freebsd.org/cgi/man.cgi?query=thr_self&sektion=2&apropos=0&manpath=FreeBSD+13.1-RELEASE+and+Ports
const freeBSDTIDMin = 100001

func tidToFreeBSD(linuxTID uint64) uint64 {
	return linuxTID + freeBSDTIDMin
}

func tidFromFreeBSD(freeBSDTID uint64) uint64 {
	return freeBSDTID - freeBSDTIDMin
}
