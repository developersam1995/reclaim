package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"reclaim/internal/config"
)

const (
	// probeTimeout bounds one connection attempt when checking for a daemon.
	probeTimeout = 500 * time.Millisecond
	// startPollInterval is how often EnsureDaemon re-checks the socket while
	// a freshly started daemon comes up.
	startPollInterval = 50 * time.Millisecond

	// The daemon output quoted when a start fails: at most logTailLines
	// non-blank lines from the last logTailBytes written by that launch,
	// each cut to logLineMax bytes.
	logTailLines = 20
	logTailBytes = 16 << 10
	logLineMax   = 300
)

func ensureDaemon(paths config.Paths, exe string, timeout time.Duration) (bool, error) {
	if paths.Socket == "" {
		return false, errors.New("ensure reclaim daemon: no socket path")
	}
	if accepting(paths.Socket) {
		return false, nil
	}
	if exe == "" {
		return false, errors.New("start reclaim daemon: no executable path")
	}
	if err := paths.EnsureDirs(); err != nil {
		return false, fmt.Errorf("start reclaim daemon: prepare directories: %w", err)
	}
	logStart, err := launchDaemon(exe, paths.DaemonLog)
	if err != nil {
		return false, err
	}
	// The child exits at once if another daemon won a start race; that
	// daemon's socket serves just as well, so keep polling regardless.
	deadline := time.Now().Add(timeout)
	for {
		if accepting(paths.Socket) {
			return true, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, startTimeoutError(paths, timeout, logStart)
		}
		time.Sleep(min(startPollInterval, remaining))
	}
}

// accepting reports whether something accepts connections on socket. The
// probe connection is closed straight away, without a hello.
func accepting(socket string) bool {
	nc, err := net.DialTimeout("unix", socket, probeTimeout)
	if err != nil {
		return false
	}
	_ = nc.Close()
	return true
}

// launchDaemon starts `exe daemon` detached from the caller: in a new session
// (no controlling terminal, out of reach of the launching shell's job control
// and hang-ups), in "/" (so it pins no directory), with stdin from /dev/null,
// stdout and stderr appended to logPath, and the environment inherited. The
// process is released and never waited for. It returns the log's size before
// the launch, which is where this launch's output begins.
func launchDaemon(exe, logPath string) (int64, error) {
	// The child runs in "/", so a relative exe must be made absolute first
	// or it would be resolved against "/".
	if strings.ContainsRune(exe, filepath.Separator) && !filepath.IsAbs(exe) {
		abs, err := filepath.Abs(exe)
		if err != nil {
			return 0, fmt.Errorf("start reclaim daemon: resolve %s: %w", exe, err)
		}
		exe = abs
	}
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("start reclaim daemon: open log: %w", err)
	}
	// The child holds its own descriptors for the log; ours is not needed
	// once it has started (or failed to).
	defer logFile.Close()

	var logStart int64
	if fi, err := logFile.Stat(); err == nil {
		logStart = fi.Size()
	}
	cmd := exec.Command(exe, "daemon")
	cmd.Dir = "/"
	cmd.Env = os.Environ()
	// cmd.Stdin stays nil: the child reads from /dev/null.
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start reclaim daemon: %w", err)
	}
	// Detach. Release only drops our handle on the child; whatever it
	// returns, the daemon is running, so its error is not a start failure.
	_ = cmd.Process.Release()
	return logStart, nil
}

// startTimeoutError reports a launched daemon that never accepted
// connections, quoting what that launch wrote to the daemon log.
func startTimeoutError(paths config.Paths, timeout time.Duration, logStart int64) error {
	msg := fmt.Sprintf("reclaim daemon did not accept connections on %s within %s", paths.Socket, timeout)
	lines, err := logTail(paths.DaemonLog, logStart)
	switch {
	case err != nil:
		return fmt.Errorf("%s (could not read %s: %v)", msg, paths.DaemonLog, err)
	case len(lines) == 0:
		return fmt.Errorf("%s and wrote nothing to %s", msg, paths.DaemonLog)
	default:
		return fmt.Errorf("%s; last lines of %s:\n    %s", msg, paths.DaemonLog, strings.Join(lines, "\n    "))
	}
}

// logTail returns the last logTailLines non-blank lines written to path at
// or after offset, reading at most logTailBytes. If the file is now shorter
// than offset (truncated or replaced meanwhile) it reads from the start.
func logTail(path string, offset int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if offset < 0 || offset > size {
		offset = 0
	}
	from := max(offset, size-logTailBytes)
	buf := make([]byte, size-from)
	n, err := f.ReadAt(buf, from)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = buf[:n]
	if from > offset {
		// The window starts mid-line; drop the fragment.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return lastLines(buf, logTailLines), nil
}

// lastLines returns the last n non-blank lines of b with trailing whitespace
// (including '\r') removed, invalid UTF-8 replaced, and each line cut to
// logLineMax bytes.
func lastLines(b []byte, n int) []string {
	if n <= 0 {
		return nil
	}
	var lines []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRightFunc(strings.ToValidUTF8(raw, "\uFFFD"), unicode.IsSpace)
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, truncate(line, logLineMax))
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}
