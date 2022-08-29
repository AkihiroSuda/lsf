package freebsd

import (
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func mmapHandler(sc *tracer.SyscallCtx) error {
	// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	if sc.Entry {
		origFlags := sc.Regs.Arg(3)
		var flags uint64
		m := map[uint64]uint64{
			freebsd.MAP_32BIT: unix.MAP_32BIT,
			// MAP_ALIGNED_SUPER: covered by the MAP_ALIGNMENT_SHIFT check below
			freebsd.MAP_ANON: unix.MAP_ANON,
			// MAP_ANONYMOUS: an alias of MAP_ANON
			freebsd.MAP_EXCL:  unix.MAP_FIXED_NOREPLACE, // since Linux 4.17
			freebsd.MAP_FIXED: unix.MAP_FIXED,
			// MAP_NOSYNC: N/A
			freebsd.MAP_PREFAULT_READ: unix.MAP_POPULATE,
			freebsd.MAP_PRIVATE:       unix.MAP_PRIVATE,
			freebsd.MAP_SHARED:        unix.MAP_SHARED,
			freebsd.MAP_STACK:         unix.MAP_STACK,
		}
		for k, v := range m {
			if origFlags&k != 0 {
				flags |= v
				origFlags &= ^k
			}
		}
		if origFlags&freebsd.MAP_GUARD != 0 {
			// ld-elf.so.1 calls MAP_GUARD with fd=-1
			logrus.Debugf("SYS_MMAP: incomplete support for MAP_GUARD")
			flags |= unix.MAP_ANON | unix.MAP_PRIVATE
			origFlags &= ^uint64(freebsd.MAP_GUARD)
		}
		if shifted := (origFlags >> freebsd.MAP_ALIGNMENT_SHIFT); shifted != 0 {
			flags |= unix.MAP_FIXED | unix.MAP_FIXED_NOREPLACE
			alignedAddr := uint64((1 << freebsd.MAP_ALIGNMENT_SHIFT) * (sc.Personality.(*personality).rand.Int63() % (1 << 20)))
			logrus.Debugf("SYS_MMAP: incomplete support for MAP_ALIGNED(%d), attempting to use a fixed address 0x%x", shifted, alignedAddr)
			sc.Regs.SetArg(0, alignedAddr)
			origFlags &= ^(shifted << freebsd.MAP_ALIGNMENT_SHIFT)
		}
		if origFlags != 0 {
			logrus.Debugf("SYS_MMAP: ignoring unsupported flags 0x%x", origFlags)
		}
		sc.Regs.SetSyscall(unix.SYS_MMAP)
		sc.Regs.SetArg(3, flags)
	} else {
		sc.Regs.AdjustRet()
	}
	return nil
}
