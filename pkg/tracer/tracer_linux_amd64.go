package tracer

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Regs is partially specific to the FreeBSD ABI
// FIXME: FreeBSD-specific part has to be moved to personalities/freebsd
type Regs struct {
	unix.PtraceRegs
}

func (regs *Regs) String() string {
	s := "["
	s += fmt.Sprintf("RAX=0x%x ORIG_RAX=0x%x RBX=0x%x RCX=0x%x RDX=0x%x RSI=0x%x RDI=0x%x RBP=0x%x RSP=0x%x ",
		regs.Rax, regs.Orig_rax, regs.Rbx, regs.Rcx, regs.Rdx, regs.Rsi, regs.Rdi, regs.Rbp, regs.Rsp)
	s += fmt.Sprintf("R8=0x%x R9=0x%x R10=0x%x R11=0x%x R12=0x%x R13=0x%x R14=0x%x R15=0x%x ",
		regs.R8, regs.R9, regs.R10, regs.R11, regs.R12, regs.R13, regs.R14, regs.R15)
	s += fmt.Sprintf("RIP=0x%x EFLAGS=0x%x CS=0x%x SS=0x%x DS=0x%x ES=0x%x FS=0x%x FSBASE=0x%x GS=0x%x GSBASE=0x%x",
		regs.Rip, regs.Eflags, regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Fs_base, regs.Gs, regs.Gs_base)
	s += "]"
	return s
}

func (regs *Regs) Syscall() uint64 {
	return regs.Orig_rax
}

func (regs *Regs) SetSyscall(x uint64) {
	regs.Orig_rax = x
}

func (regs *Regs) Ret() uint64 {
	return regs.Rax
}

const EflagsCF = 0x1

func (regs *Regs) AdjustRet() {
	if int(regs.Ret()) < 0 {
		regs.SetError()
	} else {
		regs.ClearError()
	}
}

// SetError is specific to the FreeBSD ABI
func (regs *Regs) SetError() {
	regs.Eflags |= EflagsCF
}

// ClearError is specific to the FreeBSD ABI
func (regs *Regs) ClearError() {
	regs.Eflags = uint64(int64(regs.Eflags) & ^EflagsCF)
}

func (regs *Regs) SetRet(x uint64) {
	regs.Rax = x
	regs.AdjustRet()
}

func (regs *Regs) SetErrno(x uint64) {
	regs.SetRet(uint64(-1 * int(x)))
}

func (regs *Regs) Arg(i int) uint64 {
	// FreeBSD syscall: RDI, RSI, RDX, RCX, R8, R9
	// But RCX is internally changed into R10:
	// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/amd64/amd64/exception.S#L582
	//
	// See also:
	// https://www.felixcloutier.com/x86/syscall
	// https://stackoverflow.com/questions/66878250/freebsd-syscall-clobbering-more-registers-than-linux-inline-asm-different-behav
	switch i {
	case 0:
		return regs.Rdi
	case 1:
		return regs.Rsi
	case 2:
		return regs.Rdx
	case 3:
		return regs.R10 // Not RCX!
	case 4:
		return regs.R8
	case 5:
		return regs.R9
	default:
		panic(fmt.Errorf("unexpected Arg %d", i))
	}
}

func (regs *Regs) SetArg(i int, x uint64) {
	// Linux user:    RDI, RSI, RDX, RCX, R8, R9
	// Linux syscall: RDI, RSI, RDX, R10 (Not RCX!), R8, R9
	switch i {
	case 0:
		regs.Rdi = x
	case 1:
		regs.Rsi = x
	case 2:
		regs.Rdx = x
	case 3:
		regs.R10 = x // Not RCX!
	case 4:
		regs.R8 = x
	case 5:
		regs.R9 = x
	default:
		panic(fmt.Errorf("unexpected Arg %d", i))
	}
}
