package procfs

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// systemPrefixes are root-owned trees where only root could plant a symlink;
// the walk is skipped there for speed.
var systemPrefixes = []string{"/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc", "/sys"}

const maxSymlinks = 40

func hasPrefixDir(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// rewriteSelf maps process-relative magic paths to explicit ones.
func rewriteSelf(p string, tid, tgid int) string {
	tg := strconv.Itoa(tgid)
	switch {
	case hasPrefixDir(p, "/proc/self"):
		return "/proc/" + tg + strings.TrimPrefix(p, "/proc/self")
	case hasPrefixDir(p, "/proc/thread-self"):
		return "/proc/" + tg + "/task/" + strconv.Itoa(tid) + strings.TrimPrefix(p, "/proc/thread-self")
	case hasPrefixDir(p, "/dev/fd"):
		return "/proc/" + tg + "/fd" + strings.TrimPrefix(p, "/dev/fd")
	case p == "/dev/stdin":
		return "/proc/" + tg + "/fd/0"
	case p == "/dev/stdout":
		return "/proc/" + tg + "/fd/1"
	case p == "/dev/stderr":
		return "/proc/" + tg + "/fd/2"
	}
	return p
}

func resolve(tid, tgid int, dirfd int32, raw string, followFinal, emptyPath bool) (PathInfo, error) {
	var lexical string
	switch {
	case raw == "":
		if !emptyPath || dirfd == unix.AT_FDCWD {
			return PathInfo{}, fmt.Errorf("empty path: %w", unix.ENOENT)
		}
		p, err := fdPath(tid, int(dirfd))
		if err != nil {
			return PathInfo{}, fmt.Errorf("resolve fd %d: %w", dirfd, err)
		}
		lexical = p
	case path.IsAbs(raw):
		lexical = path.Clean(raw)
	default:
		var base string
		var err error
		if dirfd == unix.AT_FDCWD {
			base, err = cwd(tid)
		} else {
			base, err = fdPath(tid, int(dirfd))
		}
		if err != nil {
			return PathInfo{}, fmt.Errorf("resolve base of %q: %w", raw, err)
		}
		if !path.IsAbs(base) { // "pipe:[1234]" and friends
			return PathInfo{}, fmt.Errorf("resolve %q against non-directory %q: %w", raw, base, unix.ENOTDIR)
		}
		lexical = path.Clean(path.Join(base, raw))
	}
	lexical = rewriteSelf(lexical, tid, tgid)
	info := PathInfo{Lexical: lexical, Resolved: lexical}
	for _, pre := range systemPrefixes {
		if hasPrefixDir(lexical, pre) {
			fillStat(&info, followFinal)
			return info, nil
		}
	}
	info.Resolved = walk(lexical, tid, tgid, followFinal)
	fillStat(&info, followFinal)
	return info, nil
}

// walk resolves symlinks component by component. It returns the lexical path
// unchanged when a /proc magic link or a symlink loop blocks resolution.
func walk(lexical string, tid, tgid int, followFinal bool) string {
	comps := strings.Split(strings.TrimPrefix(lexical, "/"), "/")
	cur := "/"
	hops := 0
	for len(comps) > 0 {
		c := comps[0]
		comps = comps[1:]
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		fi, err := os.Lstat(next)
		if err != nil {
			// Missing: append the rest lexically.
			rest := append([]string{c}, comps...)
			return path.Join(append([]string{cur}, rest...)...)
		}
		final := len(comps) == 0
		if fi.Mode()&os.ModeSymlink == 0 || (final && !followFinal) {
			cur = next
			continue
		}
		hops++
		if hops > maxSymlinks {
			return lexical
		}
		target, err := os.Readlink(next)
		if err != nil {
			return lexical
		}
		if strings.HasSuffix(target, " (deleted)") {
			return lexical
		}
		if !path.IsAbs(target) {
			if strings.HasPrefix(next, "/proc/") && strings.ContainsRune(target, ':') {
				return lexical // "pipe:[123]", "socket:[456]", "anon_inode:[eventfd]"
			}
			target = path.Join(cur, target)
		}
		target = rewriteSelf(path.Clean(target), tid, tgid)
		tcomps := strings.Split(strings.TrimPrefix(target, "/"), "/")
		comps = append(tcomps, comps...)
		cur = "/"
	}
	return cur
}

func fillStat(info *PathInfo, followFinal bool) {
	var fi os.FileInfo
	var err error
	if followFinal {
		fi, err = os.Stat(info.Resolved)
	} else {
		fi, err = os.Lstat(info.Resolved)
	}
	if err == nil {
		info.Exists = true
		info.IsDir = fi.IsDir()
	}
}

func writable(p PathInfo) bool {
	target := p.Resolved
	if target == "" {
		target = p.Lexical
	}
	if p.Exists {
		if unix.Access(target, unix.W_OK) == nil {
			return true
		}
		return unix.Access(path.Dir(target), unix.W_OK) == nil
	}
	dir := path.Dir(target)
	for dir != "/" && dir != "." {
		if _, err := os.Lstat(dir); err == nil {
			return unix.Access(dir, unix.W_OK) == nil
		}
		dir = path.Dir(dir)
	}
	return unix.Access(dir, unix.W_OK) == nil
}
