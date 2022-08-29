package freebsd

import (
	"encoding/binary"
	"os"
	"runtime"

	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func sysctlHandler(sc *tracer.SyscallCtx) error {
	mibPtr := uintptr(sc.Regs.Arg(0))
	mibN := sc.Regs.Arg(1) // the number of the integers
	if mibN >= 16 {
		if sc.Entry {
			logrus.Debugf("SYS___SYSCTL: unexpected mibN=%d", mibN)
		}
		return stubHandler(freebsd.EINVAL)(sc)
	}

	mibLen := mibN * 4
	mibB := make([]byte, mibLen)
	if _, err := unix.PtracePeekData(sc.Pid, mibPtr, mibB); err != nil {
		return err
	}
	mib := make([]uint32, mibN)
	for i := 0; i < int(mibN); i++ {
		mib[i] = binary.LittleEndian.Uint32(mibB[i*4 : (i+1)*4])
	}
	mibStr := freebsd.MibString(mib)
	if sc.Entry {
		logrus.Debugf("SYS___SYSCTL: MIB=%s (%v)", mibStr, mib)
	}
	switch mibStr {
	case "kern.ostype":
		return sysctlReturnString(sc, mib, mibStr, "FreeBSD")
	case "kern.osrelease":
		return sysctlReturnString(sc, mib, mibStr, KernOSRelease)
	case "kern.version":
		return sysctlReturnString(sc, mib, mibStr, KernVersion)
	case "kern.hostname":
		v, err := os.Hostname()
		if err != nil {
			return stubHandler(freebsd.EIO, mibStr, err.Error())(sc)
		}
		return sysctlReturnString(sc, mib, mibStr, v)
	case "kern.osreldate":
		return sysctlReturnUint32(sc, mib, mibStr, KernOSRelDate)
	case "hw.machine":
		v := runtime.GOARCH
		return sysctlReturnString(sc, mib, mibStr, v)
	default:
		return stubHandler(freebsd.ENOTSUP, mibStr)(sc)
	}
}

func sysctlReturnUint32(sc *tracer.SyscallCtx, mib []uint32, mibStr string, value uint32) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if oldLen != 4 {
			logrus.Debugf("unexpected oldLen=%d", oldLen)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := make([]byte, 4)
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %d", mibStr, value)
		binary.LittleEndian.PutUint32(oldB, value)
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func sysctlReturnString(sc *tracer.SyscallCtx, mib []uint32, mibStr string, value string) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if int(oldLen) < len(value)+1 {
			logrus.Debugf("unexpected oldLen=%d for %q", oldLen, value)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := []byte(append([]byte(value), 0x00))
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %q", mibStr, value)
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}
