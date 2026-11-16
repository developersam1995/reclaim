package procfs

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestMemStrings(t *testing.T) {
	page := os.Getpagesize()
	both, err := unix.Mmap(-1, 0, 2*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	// Unmap page 2 so that reading past page 1 faults (PROT_NONE would not:
	// /proc/pid/mem reads bypass page protections).
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, uintptr(unsafe.Pointer(&both[page])), uintptr(page), 0); errno != 0 {
		t.Fatal(errno)
	}
	buf := both[:page]
	// Short string at the very end of page 1.
	s := "hello"
	copy(buf[page-len(s)-1:], s+"\x00")
	m, err := OpenMem(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	base := uint64(uintptr(unsafe.Pointer(&buf[0])))
	got, err := m.ReadString(base+uint64(page-len(s)-1), 4096)
	if err != nil || got != s {
		t.Fatalf("ReadString at page end = %q, %v", got, err)
	}
	// A string running into the PROT_NONE page errors.
	copy(buf[page-3:], "abc")
	if _, err := m.ReadString(base+uint64(page-3), 4096); err == nil {
		t.Fatal("expected error reading into unmapped page")
	}
	// max exceeded.
	copy(buf[:], "abcdefghij\x00")
	if _, err := m.ReadString(base, 4); !errors.Is(err, unix.ENAMETOOLONG) {
		t.Fatalf("want ENAMETOOLONG, got %v", err)
	}
	// argv-like array.
	copy(buf[100:], "one\x00")
	copy(buf[200:], "two\x00")
	ptrs := buf[300:]
	binary.LittleEndian.PutUint64(ptrs[0:], base+100)
	binary.LittleEndian.PutUint64(ptrs[8:], base+200)
	binary.LittleEndian.PutUint64(ptrs[16:], 0)
	args, err := m.ReadStrings(base+300, 10, 100)
	if err != nil || strings.Join(args, ",") != "one,two" {
		t.Fatalf("ReadStrings = %v, %v", args, err)
	}
}

func TestParseSockaddr(t *testing.T) {
	in := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{10, 0, 0, 5}}
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&in.Port))[:], 22)
	b := (*[unsafe.Sizeof(in)]byte)(unsafe.Pointer(&in))[:]
	st, err := ParseSockaddr(b)
	if err != nil || st.Family != "inet" || st.IP.String() != "10.0.0.5" || st.Port != 22 {
		t.Fatalf("inet = %+v %v", st, err)
	}
	in6 := unix.RawSockaddrInet6{Family: unix.AF_INET6}
	in6.Addr[15] = 1
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&in6.Port))[:], 443)
	b = (*[unsafe.Sizeof(in6)]byte)(unsafe.Pointer(&in6))[:]
	st, err = ParseSockaddr(b)
	if err != nil || st.Family != "inet6" || st.IP.String() != "::1" || st.Port != 443 {
		t.Fatalf("inet6 = %+v %v", st, err)
	}
	un := []byte{byte(unix.AF_UNIX), 0}
	st, _ = ParseSockaddr(append(un, []byte("/run/x\x00\x00")...))
	if st.Family != "unix" || st.Path != "/run/x" {
		t.Fatalf("unix = %+v", st)
	}
	st, _ = ParseSockaddr(append(un, []byte("\x00/tmp/.X11-unix/X0")...))
	if st.Family != "abstract" || st.Path != "/tmp/.X11-unix/X0" {
		t.Fatalf("abstract = %+v", st)
	}
	st, _ = ParseSockaddr(un)
	if st.Family != "unix" || st.Path != "" {
		t.Fatalf("unnamed = %+v", st)
	}
	if _, err := ParseSockaddr([]byte{byte(unix.AF_INET), 0, 0}); err == nil {
		t.Fatal("short inet should fail")
	}
	if st, _ := ParseSockaddr([]byte{byte(unix.AF_NETLINK), 0, 0, 0}); st.Family != "other" {
		t.Fatalf("netlink = %+v", st)
	}
}

func startChild(t *testing.T, dir string, extra ...*os.File) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sh", "-c", "sleep 30")
	cmd.Dir = dir
	cmd.ExtraFiles = extra
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

func TestProcessInfo(t *testing.T) {
	dir := t.TempDir()
	cmd := startChild(t, dir)
	pid := cmd.Process.Pid
	if tg, err := Tgid(pid); err != nil || tg != pid {
		t.Fatalf("tgid = %d %v", tg, err)
	}
	if pp, err := PPid(pid); err != nil || pp != os.Getpid() {
		t.Fatalf("ppid = %d %v", pp, err)
	}
	if c := Comm(pid); c != "sh" {
		t.Fatalf("comm = %q", c)
	}
	if cl := Cmdline(pid, 200); !strings.HasPrefix(cl, "sh -c sleep") {
		t.Fatalf("cmdline = %q", cl)
	}
	if cl := Cmdline(pid, 4); cl != "sh -…" {
		t.Fatalf("truncated cmdline = %q", cl)
	}
	if w, err := Cwd(pid); err != nil || w != dir {
		t.Fatalf("cwd = %q %v", w, err)
	}
	ch := Chain(pid, os.Getpid(), 10)
	if len(ch) != 1 || ch[0].PID != pid {
		t.Fatalf("chain = %+v", ch)
	}
	if !IsDescendant(pid, os.Getpid()) || IsDescendant(os.Getpid(), pid) {
		t.Fatal("descendant check wrong")
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "a/b"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "a/b/file"), []byte("x"), 0o644))
	must(os.Symlink("b", filepath.Join(dir, "a/lnk")))                          // relative dir link
	must(os.Symlink(filepath.Join(dir, "a/b/file"), filepath.Join(dir, "abs"))) // absolute file link
	must(os.Symlink("nowhere", filepath.Join(dir, "dangling")))
	must(os.Symlink("loop2", filepath.Join(dir, "loop1")))
	must(os.Symlink("loop1", filepath.Join(dir, "loop2")))

	d, err := os.Open(dir)
	must(err)
	defer d.Close()
	cmd := startChild(t, filepath.Join(dir, "a"), d) // fd 3 = dir
	pid := cmd.Process.Pid

	cases := []struct {
		raw         string
		dirfd       int32
		follow      bool
		resolved    string
		exists, dir bool
	}{
		{"b/file", unix.AT_FDCWD, true, filepath.Join(dir, "a/b/file"), true, false},
		{"lnk/file", unix.AT_FDCWD, true, filepath.Join(dir, "a/b/file"), true, false},
		{"abs", 3, true, filepath.Join(dir, "a/b/file"), true, false},
		{"abs", 3, false, filepath.Join(dir, "abs"), true, false},
		{"dangling", 3, true, filepath.Join(dir, "nowhere"), false, false},
		{"dangling", 3, false, filepath.Join(dir, "dangling"), true, false},
		{"loop1", 3, true, filepath.Join(dir, "loop1"), false, false},
		{"a/b/missing/deeper", 3, true, filepath.Join(dir, "a/b/missing/deeper"), false, false},
		{"/usr/bin/../lib", unix.AT_FDCWD, true, "/usr/lib", true, true},
		{dir + "/a/lnk", unix.AT_FDCWD, true, filepath.Join(dir, "a/b"), true, true},
	}
	for _, c := range cases {
		info, err := Resolve(pid, pid, c.dirfd, c.raw, c.follow, false)
		if err != nil {
			t.Errorf("%q: %v", c.raw, err)
			continue
		}
		if info.Resolved != c.resolved || info.Exists != c.exists || info.IsDir != c.dir {
			t.Errorf("%q (follow=%v): got %+v, want resolved=%q exists=%v dir=%v", c.raw, c.follow, info, c.resolved, c.exists, c.dir)
		}
	}
	// /proc/self rewriting uses the child's pid; /proc/<pid>/cwd resolves to its directory.
	info, err := Resolve(pid, pid, unix.AT_FDCWD, "/proc/self/cwd/b/file", true, false)
	if err != nil || info.Resolved != filepath.Join(dir, "a/b/file") || !info.Exists {
		t.Fatalf("/proc/self/cwd = %+v %v", info, err)
	}
	if !strings.HasPrefix(info.Lexical, "/proc/"+itoa(pid)+"/cwd") {
		t.Fatalf("lexical not rewritten: %q", info.Lexical)
	}
	// /proc/<pid>/root/<path> resolves to <path>.
	info, _ = Resolve(pid, pid, unix.AT_FDCWD, "/proc/self/root"+dir+"/abs", true, false)
	if info.Resolved != filepath.Join(dir, "a/b/file") {
		t.Fatalf("/proc/self/root = %+v", info)
	}
	// An fd to a directory via AT_EMPTY_PATH.
	info, err = Resolve(pid, pid, 3, "", true, true)
	if err != nil || info.Resolved != dir || !info.IsDir {
		t.Fatalf("empty path = %+v %v", info, err)
	}
	// A pipe fd stays lexical.
	info, _ = Resolve(pid, pid, unix.AT_FDCWD, "/dev/fd/0", true, false)
	if !strings.HasPrefix(info.Lexical, "/proc/"+itoa(pid)+"/fd/0") {
		t.Fatalf("/dev/fd rewrite = %+v", info)
	}
	// Writable.
	must(os.Chmod(filepath.Join(dir, "a/b"), 0o555))
	defer os.Chmod(filepath.Join(dir, "a/b"), 0o755)
	ro := PathInfo{Lexical: filepath.Join(dir, "a/b/new"), Resolved: filepath.Join(dir, "a/b/new")}
	if os.Getuid() != 0 && Writable(ro) {
		t.Fatal("new file in read-only dir reported writable")
	}
	rw := PathInfo{Lexical: filepath.Join(dir, "x/y/z"), Resolved: filepath.Join(dir, "x/y/z")}
	if !Writable(rw) {
		t.Fatal("new path under writable dir reported unwritable")
	}
}

func itoa(i int) string { return stringsItoa(i) }

func stringsItoa(i int) string {
	var b []byte
	if i == 0 {
		return "0"
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
