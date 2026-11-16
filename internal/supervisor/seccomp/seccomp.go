// Package seccomp is Reclaim's kernel interface for seccomp user
// notification: the BPF filter (ARCHITECTURE.md §4 "Filter"), installing it,
// the notification ioctls, per-arch syscall tables, and decoding a
// notification's raw arguments into an abstract Call (no memory reads here;
// see package procfs for those).
package seccomp

import (
	"time"

	"golang.org/x/sys/unix"

	"reclaim/internal/space"
)

// Data mirrors struct seccomp_data (64 bytes).
type Data struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// Notif mirrors struct seccomp_notif (80 bytes).
type Notif struct {
	ID    uint64
	Pid   uint32 // thread id of the trapped thread, in our pid namespace
	Flags uint32
	Data  Data
}

// Resp mirrors struct seccomp_notif_resp (24 bytes).
type Resp struct {
	ID    uint64
	Val   int64
	Error int32 // negative errno, or 0
	Flags uint32
}

// FilterOptions tunes BuildFilter.
type FilterOptions struct {
	// BlockNamespaces: unshare/clone with CLONE_NEWUSER|CLONE_NEWNS → EPERM,
	// setns → EPERM, clone3 → ENOSYS.
	BlockNamespaces bool
}

// AuditArch is the AUDIT_ARCH_* value of the running architecture.
const AuditArch = auditArch

// BuildFilter assembles the classic BPF program for the running architecture.
func BuildFilter(opts FilterOptions) ([]unix.SockFilter, error) { return buildFilter(opts) }

// Install sets PR_SET_NO_NEW_PRIVS and installs prog on the CALLING THREAD
// (the caller must hold runtime.LockOSThread and exec on the same thread)
// with SECCOMP_FILTER_FLAG_NEW_LISTENER|SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
// retrying without WAIT_KILLABLE_RECV on EINVAL (kernels < 5.19). Returns the
// notification fd. Not TSYNC.
func Install(prog []unix.SockFilter) (notifyFD int, err error) { return install(prog) }

// Recv blocks until the next notification (n is zeroed first, as the kernel
// requires; EINTR is retried). A notification whose target died before
// delivery yields an error wrapping unix.ENOENT, which callers should skip.
func Recv(fd int, n *Notif) error { return recv(fd, n) }

// Poll waits up to timeout for fd to become readable. hup is true when every
// task using the filter has exited (POLLHUP) and no notification is pending.
func Poll(fd int, timeout time.Duration) (readable, hup bool, err error) { return poll(fd, timeout) }

// Continue lets the trapped syscall proceed unchanged
// (SECCOMP_USER_NOTIF_FLAG_CONTINUE).
func Continue(fd int, id uint64) error {
	return send(fd, Resp{ID: id, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE})
}

// Fail makes the trapped syscall return -1 with errno.
func Fail(fd int, id uint64, errno unix.Errno) error {
	return send(fd, Resp{ID: id, Error: -int32(errno)})
}

// IDValid reports whether notification id is still pending (its target has
// not died). Call after reading target memory and before responding.
func IDValid(fd int, id uint64) bool { return idValid(fd, id) }

// Name returns the syscall name for nr ("openat"), or "syscall_<nr>".
func Name(nr int32) string { return name(nr) }

// TrappedSyscalls lists the syscall numbers the filter sends to the supervisor.
func TrappedSyscalls() []int32 { return trapped() }

// PathArg describes one path argument of a trapped syscall.
type PathArg struct {
	Dirfd       int32    // unix.AT_FDCWD or a directory fd the path is relative to
	Ptr         uint64   // user-space address of the NUL-terminated path (0 = none)
	Op          space.Op // what the syscall does to this path
	Create      bool     // may create the final component (O_CREAT, mkdir, symlink/link/rename destination)
	FollowFinal bool     // the final symlink component is followed (open without O_NOFOLLOW, exec, chmod, truncate, connect)
	EmptyPath   bool     // AT_EMPTY_PATH: an empty path refers to Dirfd itself
	Role        string   // "path" | "source" | "dest" | "link" (symlink/link new name)
}

// SockArg describes a sockaddr argument (connect, sendto, bind).
type SockArg struct {
	Ptr uint64
	Len uint32
	Op  space.Op // space.OpConnect (connect, sendto) or space.OpListen (bind)
	FD  int32    // the socket fd
}

// Call is a decoded trapped syscall.
type Call struct {
	Nr         int32
	Name       string    // "openat"
	Paths      []PathArg // in argument order
	Sock       *SockArg
	OpenFlags  uint64 // open/openat/creat flags (raw); for openat2 see HowPtr
	HowPtr     uint64 // openat2: address of struct open_how (read flags with procfs, then OpenOp)
	ArgvPtr    uint64 // execve/execveat: address of argv (for context only)
	RenameFlag uint64 // renameat2 flags (RENAME_EXCHANGE makes both paths sources and destinations)
}

// Decode interprets a notification's syscall number and raw arguments. ok is
// false for syscalls Reclaim does not inspect (the caller should Continue).
// Open-family ops are derived with OpenOp(flags); directory-ness (list) is
// decided later by the caller after stat.
func Decode(d Data) (c Call, ok bool) { return decode(d) }

// OpenOp maps open(2) flags to an op: O_WRONLY/O_RDWR/O_CREAT/O_TRUNC →
// OpWrite (create = O_CREAT), O_DIRECTORY → OpList, else OpRead. path is true
// for O_PATH (no content access; callers allow it).
func OpenOp(flags uint64) (op space.Op, create, noFollow, path bool) { return openOp(flags) }
