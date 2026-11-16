package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Offsets into struct seccomp_data (little-endian hosts: the low word of
// args[i] is at argOffset(i), the high word 4 bytes later).
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

func argLow(i int) uint32  { return uint32(offArgs + 8*i) }
func argHigh(i int) uint32 { return uint32(offArgs + 8*i + 4) }

// Actions.
const (
	actAllow  = unix.SECCOMP_RET_ALLOW
	actNotify = unix.SECCOMP_RET_USER_NOTIF
)

func actErrno(e unix.Errno) uint32 {
	return unix.SECCOMP_RET_ERRNO | (uint32(e) & unix.SECCOMP_RET_DATA)
}

// buildFilter implements BuildFilter. See ARCHITECTURE.md §4 "Filter".
func buildFilter(opts FilterOptions) ([]unix.SockFilter, error) {
	p := &bpfProgram{}

	// 1. Architecture check.
	p.loadWord(offArch)
	p.jumpIfEqual(auditArch, "arch-ok", "bad-arch")
	p.label("bad-arch")
	p.ret(actErrno(unix.ENOSYS))
	p.label("arch-ok")
	p.loadWord(offNr)

	// 2. x32 ABI (amd64 only).
	if x32SyscallBit != 0 {
		p.jumpIfAtLeast(x32SyscallBit, "bad-arch2", fallThrough)
	}

	// 3. io_uring bypasses seccomp entirely.
	p.jumpIfEqual(uint32(unix.SYS_IO_URING_SETUP), "enosys", fallThrough)
	p.jumpIfEqual(uint32(unix.SYS_IO_URING_ENTER), "enosys", fallThrough)
	p.jumpIfEqual(uint32(unix.SYS_IO_URING_REGISTER), "enosys", fallThrough)

	// 4. seccomp: refuse nested listeners (they would take precedence).
	p.jumpIfEqual(uint32(unix.SYS_SECCOMP), "seccomp", fallThrough)

	// 5. namespaces.
	if opts.BlockNamespaces {
		p.jumpIfEqual(uint32(unix.SYS_UNSHARE), "ns-flags0", fallThrough)
		p.jumpIfEqual(uint32(unix.SYS_CLONE), "ns-flags0", fallThrough)
		p.jumpIfEqual(uint32(unix.SYS_CLONE3), "enosys", fallThrough)
		p.jumpIfEqual(uint32(unix.SYS_SETNS), "eperm", fallThrough)
	}

	// 5b. prctl(PR_SET_DUMPABLE, 0) → pretend success.
	p.jumpIfEqual(uint32(unix.SYS_PRCTL), "prctl", fallThrough)

	// 6–8. trapped syscalls, with in-kernel exemptions.
	for _, sc := range archTrapped {
		switch sc.allowIf.kind {
		case checkNone:
			p.jumpIfEqual(uint32(sc.nr), "notify", fallThrough)
		case checkFlagsSet:
			p.jumpIfEqual(uint32(sc.nr), "flags-"+sc.name, fallThrough)
		case checkNullPointer:
			p.jumpIfEqual(uint32(sc.nr), "null-"+sc.name, fallThrough)
		}
	}
	p.ret(actAllow) // everything else

	// Per-syscall argument checks.
	for _, sc := range archTrapped {
		switch sc.allowIf.kind {
		case checkFlagsSet:
			p.label("flags-" + sc.name)
			p.loadWord(argLow(sc.allowIf.arg))
			p.jumpIfAnySet(sc.allowIf.mask, "allow", "notify")
		case checkNullPointer:
			p.label("null-" + sc.name)
			p.loadWord(argLow(sc.allowIf.arg))
			p.jumpIfEqual(0, "null-hi-"+sc.name, "notify")
			p.label("null-hi-" + sc.name)
			p.loadWord(argHigh(sc.allowIf.arg))
			p.jumpIfEqual(0, "allow", "notify")
		}
	}

	// seccomp(op, flags, ...): deny SECCOMP_SET_MODE_FILTER with NEW_LISTENER.
	p.label("seccomp")
	p.loadWord(argLow(0))
	p.jumpIfEqual(unix.SECCOMP_SET_MODE_FILTER, fallThrough, "allow")
	p.loadWord(argLow(1))
	p.jumpIfAnySet(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, "eperm", "allow")

	if opts.BlockNamespaces {
		p.label("ns-flags0")
		p.loadWord(argLow(0))
		p.jumpIfAnySet(unix.CLONE_NEWUSER|unix.CLONE_NEWNS, "eperm", "allow")
	}

	// prctl(option, arg2, ...)
	p.label("prctl")
	p.loadWord(argLow(0))
	p.jumpIfEqual(unix.PR_SET_DUMPABLE, fallThrough, "allow")
	p.loadWord(argLow(1))
	p.jumpIfEqual(0, fallThrough, "allow")
	p.loadWord(argHigh(1))
	p.jumpIfEqual(0, "fake-ok", "allow")
	p.label("fake-ok")
	p.ret(actErrno(0))

	p.label("eperm")
	p.ret(actErrno(unix.EPERM))
	p.label("enosys")
	p.ret(actErrno(unix.ENOSYS))
	if x32SyscallBit != 0 {
		p.label("bad-arch2")
		p.ret(actErrno(unix.ENOSYS))
	}
	p.label("allow")
	p.ret(actAllow)
	p.label("notify")
	p.ret(actNotify)
	return p.assemble()
}

// install implements Install.
func install(prog []unix.SockFilter) (int, error) {
	if len(prog) == 0 {
		return -1, fmt.Errorf("seccomp: empty filter")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("seccomp: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&fprog)))
	if errno == unix.EINVAL {
		flags = unix.SECCOMP_FILTER_FLAG_NEW_LISTENER
		fd, _, errno = unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&fprog)))
	}
	if errno != 0 {
		return -1, fmt.Errorf("seccomp: install filter: %w", errno)
	}
	return int(fd), nil
}
