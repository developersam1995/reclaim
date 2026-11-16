package seccomp

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Compile-time layout checks against the kernel structs.
var (
	_ [64]byte = [unsafe.Sizeof(Data{})]byte{}
	_ [80]byte = [unsafe.Sizeof(Notif{})]byte{}
	_ [24]byte = [unsafe.Sizeof(Resp{})]byte{}
)

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	for {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}

func recv(fd int, n *Notif) error {
	*n = Notif{}
	if err := ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(n)); err != nil {
		return fmt.Errorf("seccomp: NOTIF_RECV: %w", err)
	}
	return nil
}

func send(fd int, r Resp) error {
	if err := ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&r)); err != nil {
		return fmt.Errorf("seccomp: NOTIF_SEND %d: %w", r.ID, err)
	}
	return nil
}

func idValid(fd int, id uint64) bool {
	return ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)) == nil
}

func poll(fd int, timeout time.Duration) (readable, hup bool, err error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	ms := int(timeout / time.Millisecond)
	if timeout < 0 {
		ms = -1
	}
	for {
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, false, fmt.Errorf("seccomp: poll: %w", err)
		}
		if n == 0 {
			return false, false, nil
		}
		re := fds[0].Revents
		readable = re&unix.POLLIN != 0
		hup = re&unix.POLLHUP != 0 && !readable
		return readable, hup, nil
	}
}
