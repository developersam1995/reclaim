package seccomp

import (
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// syscallSpec is the architecture-independent description of one trapped
// syscall: its name, how to decode its arguments, and an optional argument
// test that lets the filter allow uninteresting invocations in the kernel.
type syscallSpec struct {
	name    string
	decode  decoder
	allowIf argCheck
}

// trappedSyscall binds a syscallSpec to the running architecture's syscall
// number. Each architecture file defines archTrapped, the list of these.
type trappedSyscall struct {
	nr int32
	syscallSpec
}

// argCheck is a test on one syscall argument that the filter evaluates in the
// kernel. When it holds, the syscall is allowed without notifying the
// supervisor. The zero value never holds (always notify).
type argCheck struct {
	kind argCheckKind
	arg  int    // index into seccomp_data.args
	mask uint32 // checkFlagsSet: allow when any of these bits is set
}

// argCheckKind selects the test an argCheck performs.
type argCheckKind uint8

const (
	// checkNone: no in-kernel exemption.
	checkNone argCheckKind = iota
	// checkFlagsSet: allow when the low 32 bits of the argument (a C int
	// flags word) intersect mask.
	checkFlagsSet
	// checkNullPointer: allow when the argument (a pointer) is NULL, i.e.
	// both of its 32-bit halves are zero.
	checkNullPointer
)

// allowIfFlagsSet exempts calls whose flags argument arg has any bit of mask.
func allowIfFlagsSet(arg int, mask uint32) argCheck {
	return argCheck{kind: checkFlagsSet, arg: arg, mask: mask}
}

// allowIfNullPointer exempts calls whose pointer argument arg is NULL.
func allowIfNullPointer(arg int) argCheck {
	return argCheck{kind: checkNullPointer, arg: arg}
}

// Specs of every syscall Reclaim may trap. Which of them exist (and their
// numbers) is decided per architecture in syscalls_<arch>.go.
var (
	// O_PATH opens grant no access to file contents.
	specOpen    = syscallSpec{name: "open", decode: decodeOpen, allowIf: allowIfFlagsSet(1, unix.O_PATH)}
	specOpenat  = syscallSpec{name: "openat", decode: decodeOpenat, allowIf: allowIfFlagsSet(2, unix.O_PATH)}
	specOpenat2 = syscallSpec{name: "openat2", decode: decodeOpenat2}
	specCreat   = syscallSpec{name: "creat", decode: decodeCreat}

	specExecve   = syscallSpec{name: "execve", decode: decodeExecve}
	specExecveat = syscallSpec{name: "execveat", decode: decodeExecveat}

	specConnect = syscallSpec{name: "connect", decode: decodeConnect}
	// sendto without a destination only sends on an already connected socket.
	specSendto = syscallSpec{name: "sendto", decode: decodeSendto, allowIf: allowIfNullPointer(4)}
	specBind   = syscallSpec{name: "bind", decode: decodeBind}

	specRename    = syscallSpec{name: "rename", decode: decodeRename}
	specRenameat  = syscallSpec{name: "renameat", decode: decodeRenameat}
	specRenameat2 = syscallSpec{name: "renameat2", decode: decodeRenameat2}

	specUnlink   = syscallSpec{name: "unlink", decode: decodeRemove}
	specUnlinkat = syscallSpec{name: "unlinkat", decode: decodeUnlinkat}
	specRmdir    = syscallSpec{name: "rmdir", decode: decodeRemove}
	specMkdir    = syscallSpec{name: "mkdir", decode: decodeMkdir}
	specMkdirat  = syscallSpec{name: "mkdirat", decode: decodeMkdirat}

	specSymlink   = syscallSpec{name: "symlink", decode: decodeSymlink}
	specSymlinkat = syscallSpec{name: "symlinkat", decode: decodeSymlinkat}
	specLink      = syscallSpec{name: "link", decode: decodeLink}
	specLinkat    = syscallSpec{name: "linkat", decode: decodeLinkat}

	specTruncate  = syscallSpec{name: "truncate", decode: decodeTruncate}
	specChmod     = syscallSpec{name: "chmod", decode: decodeChmod}
	specFchmodat  = syscallSpec{name: "fchmodat", decode: decodeFchmodat}
	specFchmodat2 = syscallSpec{name: "fchmodat2", decode: decodeFchmodat2}
)

// inKernelSyscalls names the syscalls the filter decides in the kernel
// without ever notifying the supervisor (see buildFilter). They exist under
// the same names on every supported architecture.
var inKernelSyscalls = map[int32]string{
	unix.SYS_IO_URING_SETUP:    "io_uring_setup",
	unix.SYS_IO_URING_ENTER:    "io_uring_enter",
	unix.SYS_IO_URING_REGISTER: "io_uring_register",
	unix.SYS_SECCOMP:           "seccomp",
	unix.SYS_UNSHARE:           "unshare",
	unix.SYS_CLONE:             "clone",
	unix.SYS_CLONE3:            "clone3",
	unix.SYS_SETNS:             "setns",
}

// trappedByNr indexes archTrapped by syscall number.
var trappedByNr = indexTrapped(archTrapped)

func indexTrapped(table []trappedSyscall) map[int32]*trappedSyscall {
	m := make(map[int32]*trappedSyscall, len(table))
	for i := range table {
		m[table[i].nr] = &table[i]
	}
	return m
}

// name implements Name.
func name(nr int32) string {
	if sc, ok := trappedByNr[nr]; ok {
		return sc.name
	}
	if n, ok := inKernelSyscalls[nr]; ok {
		return n
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// trapped implements TrappedSyscalls: a fresh slice (callers may modify it)
// in ascending syscall-number order.
func trapped() []int32 {
	out := make([]int32, 0, len(archTrapped))
	for _, sc := range archTrapped {
		out = append(out, sc.nr)
	}
	slices.Sort(out)
	return out
}
