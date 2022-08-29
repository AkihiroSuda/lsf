package procutil

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func WaitForStopSignal(pid int) (int, unix.Signal, error) {
	var ws unix.WaitStatus
	wPid, err := unix.Wait4(pid, &ws, unix.WALL, nil)
	if err != nil {
		return 0, 0, err
	}
	if !ws.Stopped() {
		return 0, 0, fmt.Errorf("expected to be stopped (wPid=%d, ws=0x%x)", wPid, ws)
	}
	return wPid, ws.StopSignal(), nil
}

func HeadAddr(pid int) (uintptr, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsB, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, err
	}
	return headAddr(mapsB)
}

func headAddr(mapsB []byte) (uintptr, error) {
	// FIXME: implement a proper parser

	maps := strings.Split(string(mapsB), "\n")
	// Skip the "[heap]" line
	addrHex := strings.SplitN(maps[1], "-", 2)[0]
	addr, err := strconv.ParseUint(addrHex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse %q as a hex value", addrHex)
	}
	return uintptr(addr), nil
}

func ReadString(pid int, addr uintptr, bufSize int) (string, error) {
	if addr == 0 {
		return "", nil
	}
	buf := make([]byte, bufSize)
	c, err := unix.PtracePeekData(pid, addr, buf)
	if err != nil {
		return "", fmt.Errorf("failed to read 0x%x (%d bytes) from PID %d", addr, bufSize, pid)
	}
	buf = buf[:c]
	nilIdx := strings.Index(string(buf), "\x00")
	if nilIdx < 0 {
		return "", fmt.Errorf("nil byte was not found in the %d bytes", c)
	}
	return string(buf[:nilIdx]), nil
}

func GetFds(pid int, fdNums []int) ([]int, error) {
	pidFd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		err = fmt.Errorf("failed to call pidfd_open(%d): %w", pid, err)
		if errors.Is(err, unix.ENOSYS) {
			err = fmt.Errorf("%w (kernel might be older than 5.3?)", err)
		}
		return nil, err
	}
	defer unix.Close(pidFd)
	res := make([]int, len(fdNums))
	for i := range res {
		res[i] = -1
	}
	for i, fdNum := range fdNums {
		fd, err := unix.PidfdGetfd(pidFd, fdNum, 0)
		if err != nil {
			err = fmt.Errorf("failed to call pidfd_getfd(%d, %d): %w", pidFd, fdNum, err)
			if errors.Is(err, unix.ENOSYS) {
				err = fmt.Errorf("%w (kernel might be older than 5.6?)", err)
			}
			if errors.Is(err, unix.EPERM) {
				err = fmt.Errorf("%w (Hint: Running LSF inside Docker needs `docker run --security-opt seccomp=unconfined`)", err)
			}
			return res, err
		}
		res[i] = fd
	}
	return res, nil
}

func GetFd(pid, fdNum int) (int, error) {
	res, err := GetFds(pid, []int{fdNum})
	if err != nil {
		return -1, err
	}
	return res[0], nil
}
