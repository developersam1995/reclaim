package seccomp

import (
	"golang.org/x/sys/unix"

	"reclaim/internal/space"
)

// Values of PathArg.Role.
const (
	rolePath   = "path"   // the only path argument
	roleSource = "source" // rename/link: the existing name
	roleDest   = "dest"   // rename: the new name
	roleLink   = "link"   // symlink/link: the name being created
)

// decoder interprets the raw arguments of one syscall. ok is false when the
// invocation needs no inspection (the caller lets it proceed). Nr and Name
// are filled in by decode.
type decoder func(args [6]uint64) (c Call, ok bool)

// decode implements Decode. It assumes d.Arch is the native architecture: the
// filter fails every other architecture with ENOSYS before it can notify.
func decode(d Data) (Call, bool) {
	sc, ok := trappedByNr[d.Nr]
	if !ok {
		return Call{}, false
	}
	c, ok := sc.decode(d.Args)
	if !ok {
		return Call{}, false
	}
	c.Nr = d.Nr
	c.Name = sc.name
	return c, true
}

// intArg returns a C int argument (fd, dirfd). The kernel only looks at the
// low 32 bits, so AT_FDCWD (-100) decodes correctly whether the caller
// sign-extended it or left garbage in the upper half.
func intArg(raw uint64) int32 { return int32(uint32(raw)) }

// uintArg returns a C int/unsigned int argument (flags, socklen_t) as the
// kernel sees it: the low 32 bits.
func uintArg(raw uint64) uint32 { return uint32(raw) }

// openOp implements OpenOp.
//
// Only the low 32 bits of rawFlags count (open flags are a C int). With
// O_PATH the kernel ignores every flag except O_DIRECTORY, O_NOFOLLOW and
// O_CLOEXEC, so the op is list or read and nothing is created. O_TMPFILE is
// tested as a whole mask before O_DIRECTORY because it contains that bit.
// noFollow also covers O_CREAT|O_EXCL, which never follows a final symlink
// (the open fails with EEXIST instead).
func openOp(rawFlags uint64) (op space.Op, create, noFollow, path bool) {
	flags := uint32(rawFlags)
	noFollow = flags&unix.O_NOFOLLOW != 0
	if flags&unix.O_PATH != 0 {
		if flags&unix.O_DIRECTORY != 0 {
			return space.OpList, false, noFollow, true
		}
		return space.OpRead, false, noFollow, true
	}
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return space.OpWrite, true, noFollow, false
	}
	create = flags&unix.O_CREAT != 0
	if create && flags&unix.O_EXCL != 0 {
		noFollow = true
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY || create || flags&unix.O_TRUNC != 0 {
		return space.OpWrite, create, noFollow, false
	}
	if flags&unix.O_DIRECTORY != 0 {
		return space.OpList, false, noFollow, false
	}
	return space.OpRead, false, noFollow, false
}

// decodeOpenFlags builds the Call for open and openat. O_PATH opens are not
// inspected (the filter normally allows them in the kernel already).
func decodeOpenFlags(dirfd int32, pathPtr, rawFlags uint64) (Call, bool) {
	flags := uint64(uintArg(rawFlags))
	op, create, noFollow, isPath := openOp(flags)
	if isPath {
		return Call{}, false
	}
	return Call{
		Paths: []PathArg{{
			Dirfd: dirfd, Ptr: pathPtr, Op: op, Create: create,
			FollowFinal: !noFollow, Role: rolePath,
		}},
		OpenFlags: flags,
	}, true
}

// open(const char *path, int flags, mode_t mode)
func decodeOpen(a [6]uint64) (Call, bool) {
	return decodeOpenFlags(unix.AT_FDCWD, a[0], a[1])
}

// openat(int dirfd, const char *path, int flags, mode_t mode)
func decodeOpenat(a [6]uint64) (Call, bool) {
	return decodeOpenFlags(intArg(a[0]), a[1], a[2])
}

// openat2(int dirfd, const char *path, struct open_how *how, size_t size)
//
// The flags live in user memory, so the path's Op is a read placeholder; the
// caller reads how->flags and re-derives Op/Create/FollowFinal with OpenOp.
func decodeOpenat2(a [6]uint64) (Call, bool) {
	return Call{
		Paths: []PathArg{{
			Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpRead,
			FollowFinal: true, Role: rolePath,
		}},
		HowPtr: a[2],
	}, true
}

// creat(const char *path, mode_t mode), which is
// open(path, O_CREAT|O_WRONLY|O_TRUNC, mode); OpenFlags reports those flags.
func decodeCreat(a [6]uint64) (Call, bool) {
	return Call{
		Paths: []PathArg{{
			Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpWrite, Create: true,
			FollowFinal: true, Role: rolePath,
		}},
		OpenFlags: unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC,
	}, true
}

// execve(const char *path, char *const argv[], char *const envp[])
func decodeExecve(a [6]uint64) (Call, bool) {
	return Call{
		Paths: []PathArg{{
			Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpExec,
			FollowFinal: true, Role: rolePath,
		}},
		ArgvPtr: a[1],
	}, true
}

// execveat(int dirfd, const char *path, char *const argv[],
// char *const envp[], int flags)
func decodeExecveat(a [6]uint64) (Call, bool) {
	flags := uintArg(a[4])
	return Call{
		Paths: []PathArg{{
			Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpExec,
			FollowFinal: flags&unix.AT_SYMLINK_NOFOLLOW == 0,
			EmptyPath:   flags&unix.AT_EMPTY_PATH != 0,
			Role:        rolePath,
		}},
		ArgvPtr: a[2],
	}, true
}

// connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
func decodeConnect(a [6]uint64) (Call, bool) {
	return Call{Sock: &SockArg{Ptr: a[1], Len: uintArg(a[2]), Op: space.OpConnect, FD: intArg(a[0])}}, true
}

// sendto(int fd, const void *buf, size_t len, int flags,
// const struct sockaddr *dest, socklen_t addrlen)
//
// Without a destination it only sends on an already connected socket, which
// is not inspected (the filter normally allows it in the kernel already).
func decodeSendto(a [6]uint64) (Call, bool) {
	if a[4] == 0 {
		return Call{}, false
	}
	return Call{Sock: &SockArg{Ptr: a[4], Len: uintArg(a[5]), Op: space.OpConnect, FD: intArg(a[0])}}, true
}

// bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
func decodeBind(a [6]uint64) (Call, bool) {
	return Call{Sock: &SockArg{Ptr: a[1], Len: uintArg(a[2]), Op: space.OpListen, FD: intArg(a[0])}}, true
}

// renamePaths describes a rename: the source name disappears and the
// destination name is created or replaced. Neither final symlink is followed.
// With RENAME_EXCHANGE both names survive and swap; Call.RenameFlag says so.
func renamePaths(oldDirfd int32, oldPtr uint64, newDirfd int32, newPtr uint64) []PathArg {
	return []PathArg{
		{Dirfd: oldDirfd, Ptr: oldPtr, Op: space.OpWrite, Role: roleSource},
		{Dirfd: newDirfd, Ptr: newPtr, Op: space.OpWrite, Create: true, Role: roleDest},
	}
}

// rename(const char *oldpath, const char *newpath)
func decodeRename(a [6]uint64) (Call, bool) {
	return Call{Paths: renamePaths(unix.AT_FDCWD, a[0], unix.AT_FDCWD, a[1])}, true
}

// renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
func decodeRenameat(a [6]uint64) (Call, bool) {
	return Call{Paths: renamePaths(intArg(a[0]), a[1], intArg(a[2]), a[3])}, true
}

// renameat2(int olddirfd, const char *oldpath, int newdirfd,
// const char *newpath, unsigned int flags)
func decodeRenameat2(a [6]uint64) (Call, bool) {
	return Call{
		Paths:      renamePaths(intArg(a[0]), a[1], intArg(a[2]), a[3]),
		RenameFlag: uint64(uintArg(a[4])),
	}, true
}

// unlink(const char *path) and rmdir(const char *path)
func decodeRemove(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpWrite, Role: rolePath}}}, true
}

// unlinkat(int dirfd, const char *path, int flags); AT_REMOVEDIR does not
// change what is decoded.
func decodeUnlinkat(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpWrite, Role: rolePath}}}, true
}

// mkdir(const char *path, mode_t mode)
func decodeMkdir(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpWrite, Create: true, Role: rolePath}}}, true
}

// mkdirat(int dirfd, const char *path, mode_t mode)
func decodeMkdirat(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpWrite, Create: true, Role: rolePath}}}, true
}

// symlink(const char *target, const char *linkpath)
//
// Only the new link is a filesystem access; the target is stored verbatim and
// is checked when something later opens the link.
func decodeSymlink(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: unix.AT_FDCWD, Ptr: a[1], Op: space.OpWrite, Create: true, Role: roleLink}}}, true
}

// symlinkat(const char *target, int newdirfd, const char *linkpath)
func decodeSymlinkat(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: intArg(a[1]), Ptr: a[2], Op: space.OpWrite, Create: true, Role: roleLink}}}, true
}

// linkPaths describes a hard link. Linking exposes the source's contents
// under a new name, so the source counts as a read; it is followed only with
// AT_SYMLINK_FOLLOW.
func linkPaths(oldDirfd int32, oldPtr uint64, newDirfd int32, newPtr uint64, flags uint32) []PathArg {
	return []PathArg{
		{
			Dirfd: oldDirfd, Ptr: oldPtr, Op: space.OpRead,
			FollowFinal: flags&unix.AT_SYMLINK_FOLLOW != 0,
			EmptyPath:   flags&unix.AT_EMPTY_PATH != 0,
			Role:        roleSource,
		},
		{Dirfd: newDirfd, Ptr: newPtr, Op: space.OpWrite, Create: true, Role: roleLink},
	}
}

// link(const char *oldpath, const char *newpath)
func decodeLink(a [6]uint64) (Call, bool) {
	return Call{Paths: linkPaths(unix.AT_FDCWD, a[0], unix.AT_FDCWD, a[1], 0)}, true
}

// linkat(int olddirfd, const char *oldpath, int newdirfd,
// const char *newpath, int flags)
func decodeLinkat(a [6]uint64) (Call, bool) {
	return Call{Paths: linkPaths(intArg(a[0]), a[1], intArg(a[2]), a[3], uintArg(a[4]))}, true
}

// truncate(const char *path, off_t length)
func decodeTruncate(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpWrite, FollowFinal: true, Role: rolePath}}}, true
}

// chmod(const char *path, mode_t mode)
func decodeChmod(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: unix.AT_FDCWD, Ptr: a[0], Op: space.OpWrite, FollowFinal: true, Role: rolePath}}}, true
}

// fchmodat(int dirfd, const char *path, mode_t mode). The syscall has no
// flags argument (libc emulates AT_SYMLINK_NOFOLLOW), so it always follows.
func decodeFchmodat(a [6]uint64) (Call, bool) {
	return Call{Paths: []PathArg{{Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpWrite, FollowFinal: true, Role: rolePath}}}, true
}

// fchmodat2(int dirfd, const char *path, mode_t mode, unsigned int flags)
func decodeFchmodat2(a [6]uint64) (Call, bool) {
	flags := uintArg(a[3])
	return Call{Paths: []PathArg{{
		Dirfd: intArg(a[0]), Ptr: a[1], Op: space.OpWrite,
		FollowFinal: flags&unix.AT_SYMLINK_NOFOLLOW == 0,
		EmptyPath:   flags&unix.AT_EMPTY_PATH != 0,
		Role:        rolePath,
	}}}, true
}
