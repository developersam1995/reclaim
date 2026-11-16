package supervisor

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"

	"reclaim/internal/supervisor/procfs"
)

// sessionPIDs lists live processes descending from launcher.
func sessionPIDs(launcher int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == launcher {
			continue
		}
		if procfs.IsDescendant(pid, launcher) {
			out = append(out, pid)
		}
	}
	return out
}

// socketInodes returns the socket inodes open in pid.
func socketInodes(pid int, into map[uint64]bool) {
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		target, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + e.Name())
		if err != nil {
			continue
		}
		if rest, ok := strings.CutPrefix(target, "socket:["); ok {
			if ino, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64); err == nil {
				into[ino] = true
			}
		}
	}
}

// establishedRemote reports whether any inode in set is an ESTABLISHED TCP
// connection to a non-loopback peer, returning that peer.
func establishedRemote(set map[uint64]bool) (string, bool) {
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if peer, ok := scanTCP(f, set); ok {
			return peer, true
		}
	}
	return "", false
}

func scanTCP(path string, set map[uint64]bool) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != "01" { // 01 = ESTABLISHED
			continue
		}
		ino, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || !set[ino] {
			continue
		}
		ip, port := parseHexAddr(fields[2])
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true
	}
	return "", false
}

// parseHexAddr decodes "0100007F:0016" (little-endian words) into an IP and port.
func parseHexAddr(s string) (net.IP, int) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0
	}
	b, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, 0
	}
	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return nil, 0
	}
	switch len(b) {
	case 4:
		return net.IPv4(b[3], b[2], b[1], b[0]).To4(), int(port)
	case 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ { // each 32-bit word is little-endian
			ip[w*4+0], ip[w*4+1], ip[w*4+2], ip[w*4+3] = b[w*4+3], b[w*4+2], b[w*4+1], b[w*4+0]
		}
		if v4 := ip.To4(); v4 != nil {
			return v4, int(port)
		}
		return ip, int(port)
	}
	return nil, 0
}
