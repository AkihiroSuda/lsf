package freebsd

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/procutil"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func fstatHandler(sc *tracer.SyscallCtx) error {
	// int fstat(int fd, struct stat *buf);
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(nopSyscall)
	case false:
		fdNum := int32(sc.Regs.Arg(0))
		fd, err := procutil.GetFd(sc.Pid, int(fdNum))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			logrus.Debugf("SYS_FSTAT: failed to stat FD %d: %v", fdNum, err)
			sc.Regs.SetErrno(uint64(err.(syscall.Errno))) // FIXME: convert
			return nil
		}
		freebsdSt := statToFreeBSD(st)
		freebsdStB := marshalFreeBSDStat(freebsdSt)
		logrus.Debugf("SYS_FSTAT: FD %d %+v -> %+v (%d bytes)", fdNum, st, freebsdSt, len(freebsdStB))
		if _, err := unix.PtracePokeData(sc.Pid, uintptr(sc.Regs.Arg(1)), freebsdStB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func fstatatHandler(sc *tracer.SyscallCtx) error {
	// int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(nopSyscall)
	case false:
		dirfdNum := int32(sc.Regs.Arg(0))
		var (
			dirfd int
			err   error
		)
		if dirfdNum >= 0 {
			dirfd, err = procutil.GetFd(sc.Pid, int(dirfdNum))
			if err != nil {
				return err
			}
			defer unix.Close(dirfd)
		} else {
			switch dirfdNum {
			case freebsd.AT_FDCWD:
				cwdFilePath := fmt.Sprintf("/proc/%d/cwd", sc.Pid)
				dirfd, err = unix.Open(cwdFilePath, unix.O_DIRECTORY|unix.O_RDONLY, 0500)
				if err != nil {
					logrus.Debugf("SYS_FSTATAT: failed to open %q: %v", cwdFilePath, err)
					sc.Regs.SetErrno(uint64(freebsd.EIO))
					return err
				}
				defer unix.Close(dirfd)
			default:
				logrus.Debugf("SYS_FSTATAT: unexpected fdNum=%d", dirfdNum)
				sc.Regs.SetErrno(uint64(freebsd.EINVAL))
				return nil
			}
		}
		const pathnameLen = 32 // FIXME: how to predict the len?
		pathname, err := procutil.ReadString(sc.Pid, uintptr(sc.Regs.Arg(1)), pathnameLen)
		if err != nil {
			return fmt.Errorf("failed to read pathname: %w", err)
		}
		origFlags := uint64(sc.Regs.Arg(3))
		var flags uint64
		m := map[uint64]uint64{
			freebsd.AT_SYMLINK_NOFOLLOW: unix.AT_SYMLINK_NOFOLLOW,
			// TODO: AT_RESOLVE_BENEATH
			// TODO: AT_EMPTY_PATH
		}
		for k, v := range m {
			if origFlags&k != 0 {
				flags |= v
				origFlags &= ^k
			}
		}
		if origFlags != 0 {
			logrus.Debugf("SYS_FSTATAT: ignoring unsupported flags 0x%x", origFlags)
		}

		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, pathname, &st, int(flags)); err != nil {
			logrus.Debugf("SYS_FSTATAT: failed to fstatat(%d, %q, ..., %d): %v", dirfd, pathname, flags, err)
			sc.Regs.SetErrno(uint64(err.(syscall.Errno))) // FIXME: convert
			return nil
		}
		freebsdSt := statToFreeBSD(st)
		freebsdStB := marshalFreeBSDStat(freebsdSt)
		if _, err := unix.PtracePokeData(sc.Pid, uintptr(sc.Regs.Arg(2)), freebsdStB); err != nil {
			return fmt.Errorf("failed to write buf: %w", err)
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func getdirentriesHandler(sc *tracer.SyscallCtx) error {
	// ssize_t getdirentries(int fd, char	*buf, size_t nbytes, off_t *basep);
	//
	// Linux's getdents64 is similar to FreeBSD's getdirentries but a single call of Linux getents64
	// may return multiple names, so it can't be directly mapped to a single call of FreeBSD getdirentries.
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(nopSyscall)
	case false:
		fdNum := int32(sc.Regs.Arg(0))
		fd, err := procutil.GetFd(sc.Pid, int(fdNum))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		bufBeginPtr := uintptr(sc.Regs.Arg(1))
		bufSize := int(sc.Regs.Arg(2))
		const direntSize = int(unsafe.Sizeof(freebsd.Dirent{}))
		const linuxDirentSize = int(unsafe.Sizeof(unix.Dirent{}))

		bufPtr := bufBeginPtr
		linuxEntBuf := make([]byte, linuxDirentSize)
		n, err := unix.Getdents(fd, linuxEntBuf)
		if err != nil {
			sc.Regs.SetErrno(uint64(err.(syscall.Errno))) // FIXME: convert
			return nil
		}
		if n == 0 {
			sc.Regs.SetRet(0)
			return nil
		}
		linuxEntBuf = linuxEntBuf[:n]
		linuxEnt := (*unix.Dirent)(unsafe.Pointer(&linuxEntBuf[0]))
		_, _, names := unix.ParseDirent(linuxEntBuf, -1, []string{})
		// logrus.Debugf("SYS_GETDIRENTRIES: names=%v", names)
		var written int
		for i, name := range names {
			if int(bufPtr)+direntSize-1 > int(bufBeginPtr)+bufSize-1 {
				logrus.Debugf("SYS_GETDIRENTRIES: Linux returns too much names than FreeBSD expects? returning %v, discarding %v",
					names[:i], names[i:])
				sc.Regs.SetErrno(uint64(freebsd.EIO))
				return nil
			}
			// logrus.Debugf("SYS_GETDIRENTRIES: name=%v", name)
			const namlenMax = len(freebsd.Dirent{}.Name)
			var nameI8 [namlenMax]int8
			for i, c := range name {
				if i > namlenMax-1 {
					return fmt.Errorf("SYS_GETDIRENTRIES: too long name: %q", name)
				}
				nameI8[i] = int8(c)
			}
			ent := freebsd.Dirent{
				Fileno: linuxEnt.Ino,
				Off:    0, // (FIXME)
				Reclen: uint16(unsafe.Sizeof(freebsd.Dirent{})),
				Type:   linuxEnt.Type, // seems compatible?
				Namlen: uint16(len(name)),
				Name:   nameI8,
			}
			entB := marshalFreeBSDDirent(ent)
			if _, err := unix.PtracePokeData(sc.Pid, bufPtr, entB); err != nil {
				return err
			}
			bufPtr += uintptr(direntSize)
			written += direntSize
		}

		if offPtr := uintptr(sc.Regs.Arg(3)); offPtr != 0 {
			off := uint64(0) // TODO
			offB := make([]byte, 8)
			binary.LittleEndian.PutUint64(offB, off)
			if _, err := unix.PtracePokeData(sc.Pid, offPtr, offB); err != nil {
				return err
			}
		}

		sc.Regs.SetRet(uint64(written))
	}
	return nil
}

func statToFreeBSD(st unix.Stat_t) freebsd.Stat_t {
	return freebsd.Stat_t{
		Dev:   st.Dev,
		Ino:   st.Ino,
		Nlink: st.Nlink,
		Mode:  uint16(st.Mode),
		Uid:   st.Uid,
		Gid:   st.Gid,
		Rdev:  st.Rdev,
		Atim:  freebsd.Timespec(st.Atim),
		Mtim:  freebsd.Timespec(st.Mtim),
		Ctim:  freebsd.Timespec(st.Ctim),
		// Btim: N/A
		Size:    st.Size,
		Blocks:  st.Blocks,
		Blksize: int32(st.Blksize),
		// Flags: N/A
		// Gen: N/A
	}
}

func marshalFreeBSDStat(freebsdSt freebsd.Stat_t) []byte {
	const sz = int(unsafe.Sizeof(freebsd.Stat_t{}))
	return (*(*[sz]byte)(unsafe.Pointer(&freebsdSt)))[:]
}

func marshalFreeBSDDirent(freebsdDE freebsd.Dirent) []byte {
	const sz = int(unsafe.Sizeof(freebsd.Dirent{}))
	return (*(*[sz]byte)(unsafe.Pointer(&freebsdDE)))[:]
}
