package tracer

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/AkihiroSuda/lsf/pkg/procutil"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func New(personality Personality, args []string) (*Tracer, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	tracer := &Tracer{
		personality: personality,
		cmd:         cmd,
	}
	return tracer, nil
}

type Personality interface {
	HandleSyscall(sc *SyscallCtx) error
	InitNewProc(wPid int, regs *Regs) error
}

type Tracer struct {
	personality Personality
	cmd         *exec.Cmd
}

type SyscallCtx struct {
	Personality Personality
	Pid         int
	Entry       bool
	Num         uint64
	Regs        Regs
}

type SyscallHandler func(sc *SyscallCtx) error

func (tracer *Tracer) Trace() error {
	sc := &SyscallCtx{
		Personality: tracer.personality,
	}
	runtime.LockOSThread()
	err := tracer.cmd.Start()
	if err != nil {
		return err
	}
	pGid, err := unix.Getpgid(tracer.cmd.Process.Pid)
	if err != nil {
		return err
	}

	// Catch the birtycry before setting up the ptrace options
	wPid, sig, err := procutil.WaitForStopSignal(-1 * pGid)
	if err != nil {
		return err
	}
	if sig != unix.SIGTRAP {
		return fmt.Errorf("birthcry: expected SIGTRAP, got %+v", sig)
	}
	logrus.Debugf("Got birthcry, pid=%d", wPid)

	// Set up the ptrace options
	// PTRACE_O_EXITKILL: since Linux 3.8
	ptraceOptions := unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_TRACEEXIT |
		unix.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_EXITKILL
	if err := unix.PtraceSetOptions(wPid, ptraceOptions); err != nil {
		return fmt.Errorf("failed to set ptrace options: %w", err)
	}

	if err = unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
		return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
	}
	if err = tracer.personality.InitNewProc(wPid, &sc.Regs); err != nil {
		return err
	}
	if err = unix.PtraceSetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
		return fmt.Errorf("failed to set registers for %d: %w", wPid, err)
	}
	logrus.Debugf("Starting loop")
	if err := unix.PtraceSyscall(wPid, 0); err != nil {
		return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
	}
	for {
		var ws unix.WaitStatus
		wPid, err = unix.Wait4(-1*pGid, &ws, unix.WALL, nil)
		if err != nil {
			return err
		}
		switch uint32(ws) >> 8 {
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_CLONE << 8):
			logrus.Debugf("CLONE")
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_FORK << 8):
			logrus.Debugf("FORK")
			forkPid, err := unix.PtraceGetEventMsg(wPid)
			if err != nil {
				return err
			}
			if err := unix.PtraceSetOptions(int(forkPid), ptraceOptions); err != nil {
				logrus.Debugf("failed to set ptrace options for a forked process %d: %v", forkPid, err)
			}
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_VFORK << 8):
			logrus.Debugf("VFORK")
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_EXEC << 8):
			logrus.Debugf("EXEC")
			if err := unix.PtraceSingleStep(wPid); err != nil {
				return err
			}
			_, _, err := procutil.WaitForStopSignal(wPid)
			if err != nil {
				return err
			}
			if err = unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
				return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
			}
			if err = tracer.personality.InitNewProc(wPid, &sc.Regs); err != nil {
				return err
			}
			if err = unix.PtraceSetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
				return fmt.Errorf("failed to set registers for %d: %w", wPid, err)
			}
			if err := unix.PtraceSyscall(wPid, 0); err != nil {
				return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
			}
			continue
		}
		switch {
		case ws.Exited():
			exitStatus := ws.ExitStatus()
			logrus.Debugf("Process %d exited with status %d", wPid, exitStatus)
			if wPid == tracer.cmd.Process.Pid {
				logrus.Debugf("Exiting... (%d)", exitStatus)
				os.Exit(exitStatus)
			}
			if err := unix.PtraceDetach(wPid); err != nil {
				logrus.Debugf("ptrace_detach: %v", err)
			}
			continue
		case ws.Stopped():
			sig := ws.StopSignal()
			switch sig {
			// magic value 0x80: see ptrace(2), O_TRACESYSGOOD
			case 0x80 | unix.SIGTRAP:
				if err = unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
					return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
				}
				sc.Pid = wPid
				sc.Entry = !sc.Entry
				if sc.Entry {
					sc.Num = sc.Regs.Syscall()
				}
				if err := tracer.personality.HandleSyscall(sc); err != nil {
					return err
				}
				if err = unix.PtraceSetRegs(sc.Pid, &sc.Regs.PtraceRegs); err != nil {
					return fmt.Errorf("failed to set regs %s: %w", sc.Regs.String(), err)
				}
			case unix.SIGTRAP:
				logrus.Debugf("ignoring signal %v (SIGTRAP) without mask 0x80", unix.SIGTRAP)
			case unix.SIGSEGV, unix.SIGABRT, unix.SIGILL:
				if getRegErr := unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); getRegErr == nil {
					return fmt.Errorf("got signal %v PC=0x%x (regs: %s)", sig, sc.Regs.PC(), sc.Regs.String())
				}
				return fmt.Errorf("got signal %v (regs: N/A)", sig)
			default:
				logrus.Debugf("ignoring SIGSTOP (ws=%+v (0x%x))", ws, ws)
			}
		}
		if err := unix.PtraceSyscall(wPid, 0); err != nil {
			return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
		}
	}
}
