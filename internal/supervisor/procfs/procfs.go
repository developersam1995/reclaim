// Package procfs reads what the supervisor needs from /proc about a trapped
// process: its memory (path strings, sockaddrs, argv), its cwd and fds, path
// resolution from the process's point of view, and process ancestry for
// prompts. The supervisor is the target's ancestor, which Yama ptrace_scope=1
// requires for /proc/<pid>/mem access.
package procfs

import (
	"reclaim/internal/policy"
	"reclaim/internal/protocol"
)

// Mem reads a process's memory via /proc/<pid>/mem (pread). Safe for
// concurrent use; close when done.
type Mem struct{ impl *memImpl }

// OpenMem opens /proc/<pid>/mem for reading.
func OpenMem(pid int) (*Mem, error) {
	impl, err := openMem(pid)
	if err != nil {
		return nil, err
	}
	return &Mem{impl: impl}, nil
}

// Close releases the fd.
func (m *Mem) Close() error { return m.impl.close() }

// Read reads exactly n bytes at addr.
func (m *Mem) Read(addr uint64, n int) ([]byte, error) { return m.impl.read(addr, n) }

// ReadString reads a NUL-terminated string at addr of at most max bytes
// (excluding NUL), never reading across an unmapped page boundary it does not
// need (read up to each page end, then continue). Errors if no NUL within max.
func (m *Mem) ReadString(addr uint64, max int) (string, error) { return m.impl.readString(addr, max) }

// ReadStrings reads a NULL-terminated array of string pointers (argv) at addr,
// at most maxN strings of at most maxEach bytes each (longer ones truncated).
func (m *Mem) ReadStrings(addr uint64, maxN, maxEach int) ([]string, error) {
	return m.impl.readStrings(addr, maxN, maxEach)
}

// ParseSockaddr decodes a raw sockaddr: AF_INET, AF_INET6 → Family "inet"/
// "inet6" with IP and Port; AF_UNIX → "unix" with Path, or "abstract" (leading
// NUL) with the name (NULs after the first byte kept verbatim, truncated to
// the given length); anything else → Family "other".
func ParseSockaddr(b []byte) (policy.SockTarget, error) { return parseSockaddr(b) }

// Tgid returns the thread-group id (process id) of thread tid.
func Tgid(tid int) (int, error) { return tgid(tid) }

// PPid returns the parent process id of pid.
func PPid(pid int) (int, error) { return ppid(pid) }

// Comm returns /proc/<pid>/comm (trimmed).
func Comm(pid int) string { return comm(pid) }

// Cmdline returns argv joined by spaces, truncated to max bytes ("…" suffix).
func Cmdline(pid int, max int) string { return cmdline(pid, max) }

// Cwd returns the current directory of thread/process pid.
func Cwd(pid int) (string, error) { return cwd(pid) }

// FdPath returns readlink(/proc/<pid>/fd/<fd>).
func FdPath(pid, fd int) (string, error) { return fdPath(pid, fd) }

// Chain returns the process chain that led to pid, oldest first: it walks
// parent pids from pid upward and stops BEFORE stopAt (the launcher) or at pid
// 1, returning at most max entries (keeping the ones closest to pid).
func Chain(pid, stopAt, max int) []protocol.ProcInfo { return chain(pid, stopAt, max) }

// IsDescendant reports whether pid descends from ancestor (strictly).
func IsDescendant(pid, ancestor int) bool { return isDescendant(pid, ancestor) }

// PathInfo is a path argument resolved from the trapped process's view.
type PathInfo struct {
	Lexical  string // absolute & cleaned; /proc/self, /proc/thread-self, /dev/fd, /dev/std{in,out,err} rewritten to /proc/<tgid>/...
	Resolved string // symlinks (incl. /proc magic links whose target is an absolute path) resolved, best effort; non-existent tail appended lexically
	Exists   bool   // the final target exists (following the final symlink iff followFinal)
	IsDir    bool   // the final target is a directory
}

// Resolve resolves raw (as passed to the syscall by thread tid of process
// tgid) relative to dirfd (unix.AT_FDCWD → the thread's cwd, else
// /proc/<tid>/fd/<dirfd>); emptyPath with raw=="" refers to dirfd itself.
// Paths under root-owned system prefixes (/usr, /lib*, /bin, /sbin, /etc,
// /sys) skip the symlink walk (only root can plant links there). At most 40
// symlink hops.
func Resolve(tid, tgid int, dirfd int32, raw string, followFinal, emptyPath bool) (PathInfo, error) {
	return resolve(tid, tgid, dirfd, raw, followFinal, emptyPath)
}

// Writable reports whether the current user could plausibly perform a
// modification on p: W_OK on the existing target, or W_OK on its nearest
// existing parent directory. Used to skip prompts the kernel would deny anyway.
func Writable(p PathInfo) bool { return writable(p) }
