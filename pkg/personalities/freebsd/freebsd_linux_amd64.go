package freebsd

import (
	"encoding/binary"
	"fmt"

	"github.com/AkihiroSuda/lsf/pkg/alignutil"
	"github.com/AkihiroSuda/lsf/pkg/elfutil"
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/procutil"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (p *personality) InitNewProc(pid int, regs *tracer.Regs) error {
	// ===== Initialize the TLS =====
	// Call brk(NULL) to get the end of the current data segment
	brkIn := regs.PtraceRegs
	brkIn.Rax = unix.SYS_BRK
	brkIn.Rdi = 0 // NULL
	brkOut, err := procutil.InjectSyscall(pid, brkIn)
	if err != nil {
		return fmt.Errorf("failed to call the first brk: %w", err)
	}
	tlsHeadPtr := uintptr(brkOut.Rax) // The head of the TLS. The so-called "TLS ptr" is at the end on amd64.
	logrus.Debugf("tlsHeadPtr=0x%x", tlsHeadPtr)

	tlsTmpl, err := elfutil.ReadTlsTemplate(pid)
	if err != nil {
		return err
	}
	logrus.Debugf("tlsTmpl.RequiredSize=%d", tlsTmpl.RequiredSize)
	defer tlsTmpl.Close()

	// Increase the current data segment
	brkIn.Rdi = brkOut.Rax + tlsTmpl.RequiredSize
	logrus.Debugf("Increasing the data segment: 0x%x -> 0x%x", brkOut.Rax, brkIn.Rdi)
	brkOut, err = procutil.InjectSyscall(pid, brkIn)
	if err != nil {
		return fmt.Errorf("failed to call the second brk: %w", err)
	}
	if brkOut.Rax == 0 {
		return fmt.Errorf("failed to call the second brk: %v", brkOut.Rax)
	}

	// Initialize .tdata
	var tBssPtr uintptr
	if tlsTmpl.Tdata != nil {
		tDataPtr := uintptr(alignutil.Up(int(tlsHeadPtr), int(tlsTmpl.Tdata.Addralign)))
		logrus.Debugf("tDataPtr=0x%x, addralign=%d", tDataPtr, tlsTmpl.Tdata.Addralign)
		tDataB, err := tlsTmpl.Tdata.Data()
		if err != nil {
			return err
		}
		if _, err := unix.PtracePokeData(pid, tDataPtr, tDataB); err != nil {
			return fmt.Errorf("failed to poke the tdata (%d bytes) to 0x%x: %w", len(tDataB), tDataPtr, err)
		}
		tBssPtr = uintptr(int(tDataPtr) + len(tDataB))
	}

	// Initialize .tbss
	if tlsTmpl.Tbss != nil {
		if tBssPtr == 0 {
			tBssPtr = tlsHeadPtr // aligned in the next line
		}
		tBssPtr = uintptr(alignutil.Up(int(tBssPtr), int(tlsTmpl.Tbss.Addralign)))
		logrus.Debugf("tBssPtr= 0x%x, addralign=%d", tBssPtr, tlsTmpl.Tbss.Addralign)
		tBssB := make([]byte, tlsTmpl.Tbss.Size)
		if _, err := unix.PtracePokeData(pid, tBssPtr, tBssB); err != nil {
			return fmt.Errorf("failed to poke the tbss (%d bytes) to 0x%x: %w", len(tBssB), tBssPtr, err)
		}
	}

	// "there must be a pointer at the start of it that points to itself."
	// https://wiki.osdev.org/Thread_Local_Storage
	tlsSelfPtr := uintptr(uint64(tlsHeadPtr) + tlsTmpl.RequiredSize - 8)
	logrus.Debugf("tlsSelfPtr=0x%d", tlsSelfPtr)
	tlsSelfPtrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(tlsSelfPtrB, uint64(tlsSelfPtr))
	if _, err := unix.PtracePokeData(pid, tlsSelfPtr, tlsSelfPtrB); err != nil {
		return fmt.Errorf("failed to poke the tls self ptr to 0x%x: %w", tlsSelfPtr, err)
	}

	// ===== Setup the stack =====
	// Linux:   RSP=stack,         RDI=argc, RSI=argv, RDX=envp
	// FreeBSD: RSP=aligned stack, RDI=stack
	// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/amd64/amd64/exec_machdep.c#L395
	logrus.Debugf("newproc: adjusting regs %s", regs.String())
	stack := regs.Rsp
	regs.Rsp = ((stack - 8) & ^uint64(0xF)) + 8
	regs.Rdi = stack
	regs.Fs_base = uint64(tlsSelfPtr)
	logrus.Debugf("newproc: adjusted  regs %s", regs.String())

	// ===== Initialize the auxv ===
	auxvSlice, auxvPtr, err := elfutil.PeekAuxv(pid, uintptr(stack))
	if err != nil {
		return fmt.Errorf("failed to peek auxv (pid=%v): %w", pid, err)
	}
	for i := range auxvSlice {
		auxv := &auxvSlice[i]
		// logrus.Debugf("auxv: adjusting A_type=%02d, A_val=0x%x", auxv.A_type, auxv.A_val)
		switch auxv.A_type {
		case elfutil.AT_NULL:
			auxv.A_type = freebsd.AT_NULL
		case elfutil.AT_IGNORE:
			auxv.A_type = freebsd.AT_IGNORE
		case elfutil.AT_EXECFD:
			auxv.A_type = freebsd.AT_EXECFD
		case elfutil.AT_PHDR:
			auxv.A_type = freebsd.AT_PHDR
		case elfutil.AT_PHENT:
			auxv.A_type = freebsd.AT_PHENT
		case elfutil.AT_PHNUM:
			auxv.A_type = freebsd.AT_PHNUM
		case elfutil.AT_PAGESZ:
			auxv.A_type = freebsd.AT_PAGESZ
		case elfutil.AT_BASE:
			auxv.A_type = freebsd.AT_BASE
			logrus.Debugf("AT_BASE=0x%x", auxv.A_val)
			if auxv.A_val == 0 {
				logrus.Debugf("AT_BASE is zero, replacing")
				headAddr, err := procutil.HeadAddr(pid)
				if err != nil {
					return err
				}
				auxv.A_val = uint64(headAddr)
				logrus.Debugf("AT_BASE=0x%x", auxv.A_val)
			}
		case elfutil.AT_FLAGS:
			auxv.A_type = freebsd.AT_FLAGS
			// A_val seems always 0 on x86_64, no conversion is needed
		case elfutil.AT_ENTRY:
			auxv.A_type = freebsd.AT_ENTRY
		case elfutil.AT_NOTELF:
			auxv.A_type = freebsd.AT_NOTELF
		case elfutil.AT_UID:
			auxv.A_type = freebsd.AT_UID
		case elfutil.AT_EUID:
			auxv.A_type = freebsd.AT_EUID
		case elfutil.AT_GID:
			auxv.A_type = freebsd.AT_GID
		case elfutil.AT_EGID:
			auxv.A_type = freebsd.AT_EGID
		default:
			auxv.A_type = freebsd.AT_IGNORE
		}
		// logrus.Debugf("auxv: adjusted  A_type=%02d, A_val=0x%x", auxv.A_type, auxv.A_val)
	}
	if err := elfutil.PokeAuxv(pid, auxvPtr, auxvSlice); err != nil {
		return fmt.Errorf("failed to poke auxv 0x%x (pid=%v): %w", auxvPtr, pid, err)
	}

	return nil
}

func sysarchHandler(sc *tracer.SyscallCtx) error {
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(nopSyscall)
	case false:
		switch sc.Regs.Arg(0) {
		case freebsd.AMD64_SET_FSBASE:
			fsBasePtr := uintptr(sc.Regs.Arg(1))
			fsBase := make([]byte, 8)
			if _, err := unix.PtracePeekData(sc.Pid, fsBasePtr, fsBase); err != nil {
				return err
			}
			sc.Regs.Fs_base = binary.LittleEndian.Uint64(fsBase)
			sc.Regs.SetRet(0)
		default:
			logrus.Debugf("SYS_SYSARCH (%d): unknown arg %d. returning -ENOTSUP", sc.Regs.Arg(0), freebsd.SYS_SYSARCH)
			ret := -1 * int(freebsd.ENOTSUP)
			sc.Regs.SetRet(uint64(ret))
		}
	}
	return nil
}
