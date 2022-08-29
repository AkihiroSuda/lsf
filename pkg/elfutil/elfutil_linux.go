package elfutil

// NOTE: 64-bit little endian architecture is assumed

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/AkihiroSuda/lsf/pkg/alignutil"
	"golang.org/x/sys/unix"
)

type TlsTemplate struct {
	RequiredSize uint64 // including the TLS pointer (at the end, on amd64)
	Tdata        *elf.Section
	Tbss         *elf.Section
	ElfFile      *elf.File
}

func (x *TlsTemplate) Close() error {
	if x.ElfFile == nil {
		return nil
	}
	return x.ElfFile.Close()
}

func ReadTlsTemplate(pid int) (*TlsTemplate, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	elfFile, err := elf.Open(exePath)
	if err != nil {
		return nil, err
	}
	x := &TlsTemplate{
		RequiredSize: 8, // the size of the TLS pointer
	}
	for _, sec := range elfFile.Sections {
		sec := sec
		switch sec.Name {
		case ".tdata":
			x.Tdata = sec
		case ".tbss":
			x.Tbss = sec
		}
	}
	if x.Tdata != nil {
		x.RequiredSize += x.Tdata.Size
	}
	if x.Tbss != nil {
		aligned := x.RequiredSize
		switch x.Tbss.Addralign {
		case 0, 1:
			// NOP
		default:
			aligned = uint64(alignutil.Up(int(x.RequiredSize), int(x.Tbss.Addralign)))
		}
		x.RequiredSize = aligned + x.Tbss.Size
	}
	return x, nil
}

func PeekAuxv(pid int, stackPtr uintptr) ([]Elf64_auxv_t, uintptr, error) {
	stackDumpSize := 1024
	stackDump := make([]byte, stackDumpSize)
	if _, err := unix.PtracePeekData(pid, stackPtr, stackDump); err != nil {
		return nil, 0, fmt.Errorf("failed to dump stack 0x%x (size=%d, pid=%d): %w", stackPtr, stackDumpSize, pid, err)
	}
	idx := 0 // argc
	argc := binary.LittleEndian.Uint64(stackDump[0:8])
	idx += 8               // argv[0]
	idx += 8 * int(argc+1) // envp[0]
	for {
		envPtr := binary.LittleEndian.Uint64(stackDump[idx : idx+8])
		// logrus.Debugf("envptr 0x%x", envPtr)
		idx += 8
		if idx > len(stackDump)-1 {
			return nil, 0, fmt.Errorf("stack[0x%x]: too many envs?", idx)
		}
		if envPtr == 0 {
			break
		}
	}
	var auxvSlice []Elf64_auxv_t
	auxvBegin := idx
	for {
		auxv := Elf64_auxv_t{
			A_type: binary.LittleEndian.Uint64(stackDump[idx : idx+8]),
			A_val:  binary.LittleEndian.Uint64(stackDump[idx+8 : idx+16]),
		}
		auxvSlice = append(auxvSlice, auxv)
		idx += 16
		if idx > len(stackDump)-1 {
			return auxvSlice, stackPtr + uintptr(auxvBegin), fmt.Errorf("stack[0x%x]: too many auxv?", idx)
		}
		if auxv.A_type == 0 {
			break
		}
	}
	return auxvSlice, stackPtr + uintptr(auxvBegin), nil
}

func PokeAuxv(pid int, addr uintptr, auxvSlice []Elf64_auxv_t) error {
	b := make([]byte, 16*len(auxvSlice))
	var idx int
	for _, auxv := range auxvSlice {
		binary.LittleEndian.PutUint64(b[idx:idx+8], auxv.A_type)
		binary.LittleEndian.PutUint64(b[idx+8:idx+16], auxv.A_val)
		idx += 16
	}
	if _, err := unix.PtracePokeData(pid, addr, b); err != nil {
		return err
	}
	return nil
}

type Elf64_auxv_t struct {
	A_type uint64
	A_val  uint64
}

// https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/auxvec.h
const (
	AT_NULL          = 0
	AT_IGNORE        = 1
	AT_EXECFD        = 2
	AT_PHDR          = 3
	AT_PHENT         = 4
	AT_PHNUM         = 5
	AT_PAGESZ        = 6
	AT_BASE          = 7
	AT_FLAGS         = 8
	AT_ENTRY         = 9
	AT_NOTELF        = 10
	AT_UID           = 11
	AT_EUID          = 12
	AT_GID           = 13
	AT_EGID          = 14
	AT_PLATFORM      = 15
	AT_HWCAP         = 16
	AT_CLKTCK        = 17
	AT_SECURE        = 23
	AT_BASE_PLATFORM = 24
	AT_RANDOM        = 25
	AT_HWCAP2        = 26
	AT_EXECFN        = 31
	AT_MINSIGSTKSZ   = 51
)
