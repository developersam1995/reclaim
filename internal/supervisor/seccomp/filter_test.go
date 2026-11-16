package seccomp

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// run interprets a classic BPF program over a seccomp_data image. Only the
// instruction subset the builder emits is supported.
func run(t *testing.T, prog []unix.SockFilter, d Data) uint32 {
	t.Helper()
	buf := make([]byte, 64)
	binary.LittleEndian.PutUint32(buf[0:], uint32(d.Nr))
	binary.LittleEndian.PutUint32(buf[4:], d.Arch)
	binary.LittleEndian.PutUint64(buf[8:], d.InstructionPointer)
	for i, a := range d.Args {
		binary.LittleEndian.PutUint64(buf[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = binary.LittleEndian.Uint32(buf[in.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if acc >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if acc&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unsupported opcode %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func data(nr int32, args ...uint64) Data {
	d := Data{Nr: nr, Arch: auditArch}
	copy(d.Args[:], args)
	return d
}

func TestFilter(t *testing.T) {
	prog, err := BuildFilter(FilterOptions{BlockNamespaces: true})
	if err != nil {
		t.Fatal(err)
	}
	enosys := actErrno(unix.ENOSYS)
	eperm := actErrno(unix.EPERM)
	cases := []struct {
		name string
		d    Data
		want uint32
	}{
		{"read allowed", data(unix.SYS_READ), actAllow},
		{"getpid allowed", data(unix.SYS_GETPID), actAllow},
		{"openat notifies", data(unix.SYS_OPENAT, 0xffffff9c, 0x1000, unix.O_RDONLY), actNotify},
		{"openat O_PATH allowed", data(unix.SYS_OPENAT, 0xffffff9c, 0x1000, unix.O_PATH), actAllow},
		{"connect notifies", data(unix.SYS_CONNECT, 3, 0x1000, 16), actNotify},
		{"sendto null allowed", data(unix.SYS_SENDTO, 3, 0x1000, 10, 0, 0, 0), actAllow},
		{"sendto addr notifies", data(unix.SYS_SENDTO, 3, 0x1000, 10, 0, 0x2000, 16), actNotify},
		{"sendto high-word addr notifies", data(unix.SYS_SENDTO, 3, 0x1000, 10, 0, 1<<40, 16), actNotify},
		{"execve notifies", data(unix.SYS_EXECVE, 0x1000), actNotify},
		{"unlinkat notifies", data(unix.SYS_UNLINKAT), actNotify},
		{"io_uring enosys", data(unix.SYS_IO_URING_SETUP), enosys},
		{"seccomp listener eperm", data(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER), eperm},
		{"seccomp plain allowed", data(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0), actAllow},
		{"seccomp get action avail allowed", data(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0), actAllow},
		{"unshare newuser eperm", data(unix.SYS_UNSHARE, unix.CLONE_NEWUSER), eperm},
		{"unshare newns eperm", data(unix.SYS_UNSHARE, unix.CLONE_NEWNS), eperm},
		{"unshare files allowed", data(unix.SYS_UNSHARE, unix.CLONE_FILES), actAllow},
		{"clone newuser eperm", data(unix.SYS_CLONE, unix.CLONE_NEWUSER|uint64(unix.SIGCHLD)), eperm},
		{"clone plain allowed", data(unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_VFORK|uint64(unix.SIGCHLD)), actAllow},
		{"clone3 enosys", data(unix.SYS_CLONE3), enosys},
		{"setns eperm", data(unix.SYS_SETNS), eperm},
		{"prctl dumpable 0 faked", data(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0), actErrno(0)},
		{"prctl dumpable 1 allowed", data(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 1), actAllow},
		{"prctl name allowed", data(unix.SYS_PRCTL, unix.PR_SET_NAME, 0x1000), actAllow},
		{"wrong arch", Data{Nr: unix.SYS_READ, Arch: 0x40000028}, enosys},
	}
	if x32SyscallBit != 0 {
		cases = append(cases, struct {
			name string
			d    Data
			want uint32
		}{"x32 enosys", data(x32SyscallBit | 2), enosys})
	}
	for _, c := range cases {
		if got := run(t, prog, c.d); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
	for _, nr := range TrappedSyscalls() {
		d := data(nr, 0xffffff9c, 0x1000, 0, 0, 0x2000, 16) // args chosen so no exemption fires
		if nr == unix.SYS_SENDTO {
			d = data(nr, 3, 0x1000, 10, 0, 0x2000, 16)
		}
		if got := run(t, prog, d); got != actNotify {
			t.Errorf("%s (%d): got %#x, want notify", Name(nr), nr, got)
		}
	}
}

func TestFilterNamespacesAllowed(t *testing.T) {
	prog, err := BuildFilter(FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []Data{data(unix.SYS_UNSHARE, unix.CLONE_NEWUSER), data(unix.SYS_CLONE3), data(unix.SYS_SETNS)} {
		if got := run(t, prog, d); got != actAllow {
			t.Errorf("%s: got %#x, want allow", Name(d.Nr), got)
		}
	}
}

func TestDecodeAndOpenOp(t *testing.T) {
	c, ok := Decode(data(unix.SYS_OPENAT, 0xffffff9c, 0x1000, unix.O_WRONLY|unix.O_CREAT))
	if !ok || c.Name != "openat" || len(c.Paths) != 1 || c.Paths[0].Dirfd != unix.AT_FDCWD || c.Paths[0].Op != "write" || !c.Paths[0].Create {
		t.Fatalf("openat decode = %+v %v", c, ok)
	}
	if _, ok := Decode(data(unix.SYS_READ)); ok {
		t.Fatal("read should not decode")
	}
	c, ok = Decode(data(unix.SYS_RENAMEAT2, 5, 0x1, 6, 0x2, unix.RENAME_EXCHANGE))
	if !ok || len(c.Paths) != 2 || c.Paths[0].Role != "source" || c.Paths[1].Role != "dest" || c.RenameFlag != unix.RENAME_EXCHANGE || c.Paths[0].Dirfd != 5 {
		t.Fatalf("renameat2 decode = %+v", c)
	}
	c, ok = Decode(data(unix.SYS_LINKAT, 0xffffff9c, 0x1, 0xffffff9c, 0x2, unix.AT_SYMLINK_FOLLOW))
	if !ok || c.Paths[0].Op != "read" || !c.Paths[0].FollowFinal || c.Paths[1].Role != "link" {
		t.Fatalf("linkat decode = %+v", c)
	}
	if _, ok := Decode(data(unix.SYS_SENDTO, 3, 0, 0, 0, 0, 0)); ok {
		t.Fatal("sendto without address should not decode")
	}
	op, create, nofollow, path := OpenOp(unix.O_TMPFILE | unix.O_RDWR)
	if op != "write" || !create || nofollow || path {
		t.Fatalf("O_TMPFILE = %v %v %v %v", op, create, nofollow, path)
	}
	if op, _, _, _ := OpenOp(unix.O_RDONLY | unix.O_DIRECTORY); op != "list" {
		t.Fatalf("O_DIRECTORY = %v", op)
	}
	if _, _, _, path := OpenOp(unix.O_PATH); !path {
		t.Fatal("O_PATH not detected")
	}
	if Name(unix.SYS_OPENAT) != "openat" || Name(99999) != "syscall_99999" {
		t.Fatal("names wrong")
	}
}
