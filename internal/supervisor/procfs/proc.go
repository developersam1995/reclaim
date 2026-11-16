package procfs

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"reclaim/internal/protocol"
)

func procPath(pid int, parts ...string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + strings.Join(parts, "/")
}

func tgid(tid int) (int, error) {
	f, err := os.Open(procPath(tid, "status"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("/proc/%d/status: no Tgid line", tid)
}

// statFields returns the fields of /proc/<pid>/stat after the comm field.
func statFields(pid int) ([]string, error) {
	b, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		return nil, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 > len(b) {
		return nil, fmt.Errorf("/proc/%d/stat: malformed", pid)
	}
	return strings.Fields(string(b[i+2:])), nil // [state ppid pgrp ...]
}

func ppid(pid int) (int, error) {
	f, err := statFields(pid)
	if err != nil {
		return 0, err
	}
	if len(f) < 2 {
		return 0, fmt.Errorf("/proc/%d/stat: too few fields", pid)
	}
	return strconv.Atoi(f[1])
}

func comm(pid int) string {
	b, err := os.ReadFile(procPath(pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func cmdline(pid, max int) string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil {
		return ""
	}
	b = bytes.TrimRight(b, "\x00")
	s := strings.ReplaceAll(string(b), "\x00", " ")
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func cwd(pid int) (string, error) { return os.Readlink(procPath(pid, "cwd")) }

func fdPath(pid, fd int) (string, error) {
	return os.Readlink(procPath(pid, "fd", strconv.Itoa(fd)))
}

func chain(pid, stopAt, max int) []protocol.ProcInfo {
	var out []protocol.ProcInfo
	cur := pid
	for steps := 0; steps < 64 && cur > 1 && cur != stopAt; steps++ {
		out = append(out, protocol.ProcInfo{PID: cur, Comm: comm(cur), Cmdline: cmdline(cur, 200)})
		p, err := ppid(cur)
		if err != nil {
			break
		}
		cur = p
	}
	// out is newest-first; reverse to oldest-first, keep the max closest to pid.
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func isDescendant(pid, ancestor int) bool {
	cur := pid
	for steps := 0; steps < 128 && cur > 1; steps++ {
		p, err := ppid(cur)
		if err != nil {
			return false
		}
		if p == ancestor {
			return true
		}
		cur = p
	}
	return false
}
