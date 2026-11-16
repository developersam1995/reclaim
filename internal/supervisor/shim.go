package supervisor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"

	"reclaim/internal/supervisor/seccomp"
)

// ShimOptsEnv carries seccomp.FilterOptions (JSON) from the launcher to the shim.
const ShimOptsEnv = "RECLAIM_SHIM_OPTS"

// shimFD is the socketpair end the launcher passes to the shim.
const shimFD = 3

func maybeShim() {
	if len(os.Args) < 3 || os.Args[1] != ShimArg {
		return
	}
	runtime.LockOSThread()
	argv := os.Args[2:]
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "reclaim: "+format+"\n", args...)
		os.Exit(127)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		fail("%v", err)
	}
	var opts seccomp.FilterOptions
	if v := os.Getenv(ShimOptsEnv); v != "" {
		if err := json.Unmarshal([]byte(v), &opts); err != nil {
			fail("bad %s: %v", ShimOptsEnv, err)
		}
	}
	os.Unsetenv(ShimOptsEnv)
	prog, err := seccomp.BuildFilter(opts)
	if err != nil {
		fail("build filter: %v", err)
	}
	fd, err := seccomp.Install(prog)
	if err != nil {
		fail("%v (seccomp user notification needs Linux ≥ 5.0 and an unrestricted seccomp policy)", err)
	}
	if err := unix.Sendmsg(shimFD, []byte{1}, unix.UnixRights(fd), nil, 0); err != nil {
		fail("hand notify fd to launcher: %v", err)
	}
	unix.Close(fd)
	ack := make([]byte, 1)
	for {
		n, err := unix.Read(shimFD, ack)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 || ack[0] != 1 {
			fail("launcher went away before the session started")
		}
		break
	}
	unix.Close(shimFD)
	err = unix.Exec(path, argv, os.Environ())
	fail("exec %s: %v", path, err)
}
