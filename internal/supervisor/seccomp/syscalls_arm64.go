package seccomp

import "golang.org/x/sys/unix"

// auditArch is the seccomp_data.arch value of native AArch64 syscalls.
const auditArch = unix.AUDIT_ARCH_AARCH64

// x32SyscallBit is zero: AArch64 has no second syscall ABI sharing its
// AUDIT_ARCH value (32-bit ARM compat calls carry AUDIT_ARCH_ARM and are
// rejected by the architecture check).
const x32SyscallBit = 0

// archTrapped lists the syscalls sent to the supervisor on AArch64. The
// generic syscall table has no open, creat, rename, unlink, rmdir, mkdir,
// symlink, link or chmod; libc implements them with the *at forms below.
var archTrapped = []trappedSyscall{
	{unix.SYS_OPENAT, specOpenat},
	{unix.SYS_OPENAT2, specOpenat2},
	{unix.SYS_EXECVE, specExecve},
	{unix.SYS_EXECVEAT, specExecveat},
	{unix.SYS_CONNECT, specConnect},
	{unix.SYS_SENDTO, specSendto},
	{unix.SYS_BIND, specBind},
	{unix.SYS_RENAMEAT, specRenameat},
	{unix.SYS_RENAMEAT2, specRenameat2},
	{unix.SYS_UNLINKAT, specUnlinkat},
	{unix.SYS_MKDIRAT, specMkdirat},
	{unix.SYS_SYMLINKAT, specSymlinkat},
	{unix.SYS_LINKAT, specLinkat},
	{unix.SYS_TRUNCATE, specTruncate},
	{unix.SYS_FCHMODAT, specFchmodat},
	{unix.SYS_FCHMODAT2, specFchmodat2},
}
