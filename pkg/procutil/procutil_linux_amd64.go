package procutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func InjectSyscall(pid int, regs unix.PtraceRegs) (*unix.PtraceRegs, error) {
	var regsBak unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regsBak); err != nil {
		return nil, err
	}
	if regs.Rip == 0 {
		regs.Rip = regsBak.Rip
	}
	rip := regs.Rip
	textBak := make([]byte, 2)
	if _, err := unix.PtracePeekText(pid, uintptr(rip), textBak); err != nil {
		return nil, err
	}
	restore := func() {
		if _, err := unix.PtracePokeText(pid, uintptr(rip), textBak); err != nil {
			panic(err)
		}
		if err := unix.PtraceSetRegs(pid, &regsBak); err != nil {
			panic(err)
		}
	}
	defer restore()

	// https://www.felixcloutier.com/x86/syscall.html
	syscallInst := []byte{0x0F, 0x05}
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return nil, err
	}
	if _, err := unix.PtracePokeText(pid, uintptr(rip), syscallInst); err != nil {
		return nil, err
	}
	if err := unix.PtraceSingleStep(pid); err != nil {
		return nil, err
	}
	_, sig, err := WaitForStopSignal(pid)
	if err != nil {
		return nil, err
	}
	if sig != unix.SIGTRAP {
		return nil, fmt.Errorf("expected SIGTRAP, got %+v", sig)
	}
	var regsResult unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regsResult); err != nil {
		return nil, err
	}
	return &regsResult, nil
}
