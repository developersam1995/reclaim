package seccomp

import "golang.org/x/sys/unix"

// auditArch is the seccomp_data.arch value of native x86-64 syscalls.
const auditArch = unix.AUDIT_ARCH_X86_64

// x32SyscallBit (__X32_SYSCALL_BIT) marks x32-ABI syscall numbers. x32 calls
// carry AUDIT_ARCH_X86_64 too, so the filter rejects these numbers itself.
const x32SyscallBit = 0x40000000

// archTrapped lists the syscalls sent to the supervisor on x86-64, including
// the legacy path syscalls that newer architectures only offer as *at forms.
var archTrapped = []trappedSyscall{
	{unix.SYS_OPEN, specOpen},
	{unix.SYS_OPENAT, specOpenat},
	{unix.SYS_OPENAT2, specOpenat2},
	{unix.SYS_CREAT, specCreat},
	{unix.SYS_EXECVE, specExecve},
	{unix.SYS_EXECVEAT, specExecveat},
	{unix.SYS_CONNECT, specConnect},
	{unix.SYS_SENDTO, specSendto},
	{unix.SYS_BIND, specBind},
	{unix.SYS_RENAME, specRename},
	{unix.SYS_RENAMEAT, specRenameat},
	{unix.SYS_RENAMEAT2, specRenameat2},
	{unix.SYS_UNLINK, specUnlink},
	{unix.SYS_UNLINKAT, specUnlinkat},
	{unix.SYS_RMDIR, specRmdir},
	{unix.SYS_MKDIR, specMkdir},
	{unix.SYS_MKDIRAT, specMkdirat},
	{unix.SYS_SYMLINK, specSymlink},
	{unix.SYS_SYMLINKAT, specSymlinkat},
	{unix.SYS_LINK, specLink},
	{unix.SYS_LINKAT, specLinkat},
	{unix.SYS_TRUNCATE, specTruncate},
	{unix.SYS_CHMOD, specChmod},
	{unix.SYS_FCHMODAT, specFchmodat},
	{unix.SYS_FCHMODAT2, specFchmodat2},
}
