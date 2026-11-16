package procfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"reclaim/internal/policy"
)

type memImpl struct {
	fd   int
	page uint64
}

func openMem(pid int) (*memImpl, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/mem", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /proc/%d/mem: %w", pid, err)
	}
	return &memImpl{fd: fd, page: uint64(os.Getpagesize())}, nil
}

func (m *memImpl) close() error { return unix.Close(m.fd) }

func (m *memImpl) read(addr uint64, n int) ([]byte, error) {
	if addr >= 1<<63 || n < 0 {
		return nil, fmt.Errorf("read %d bytes at %#x: %w", n, addr, unix.EFAULT)
	}
	buf := make([]byte, n)
	got := 0
	for got < n {
		k, err := unix.Pread(m.fd, buf[got:], int64(addr)+int64(got))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %d bytes at %#x: %w", n, addr, err)
		}
		if k == 0 {
			return nil, fmt.Errorf("read %d bytes at %#x: short read: %w", n, addr, unix.EFAULT)
		}
		got += k
	}
	return buf, nil
}

// readString reads page by page so that a short string at the end of a
// mapping never faults on the unmapped page after it.
func (m *memImpl) readString(addr uint64, max int) (string, error) {
	var out []byte
	for len(out) <= max {
		chunk := int(m.page - addr%m.page)
		if remaining := max + 1 - len(out); chunk > remaining {
			chunk = remaining
		}
		b, err := m.read(addr, chunk)
		if err != nil {
			return "", err
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(append(out, b[:i]...)), nil
		}
		out = append(out, b...)
		addr += uint64(chunk)
	}
	return "", fmt.Errorf("string at %#x longer than %d bytes: %w", addr, max, unix.ENAMETOOLONG)
}

func (m *memImpl) readStrings(addr uint64, maxN, maxEach int) ([]string, error) {
	var out []string
	for i := 0; i < maxN; i++ {
		b, err := m.read(addr+uint64(8*i), 8)
		if err != nil {
			return out, err
		}
		p := binary.LittleEndian.Uint64(b)
		if p == 0 {
			return out, nil
		}
		s, err := m.readString(p, maxEach)
		if err != nil {
			if errors.Is(err, unix.ENAMETOOLONG) {
				// Truncate instead of failing: argument strings can be huge.
				if b, rerr := m.read(p, maxEach); rerr == nil {
					if j := bytes.IndexByte(b, 0); j >= 0 {
						b = b[:j]
					}
					out = append(out, string(b)+"…")
					continue
				}
			}
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

func parseSockaddr(b []byte) (policy.SockTarget, error) {
	if len(b) < 2 {
		return policy.SockTarget{}, fmt.Errorf("sockaddr of %d bytes: %w", len(b), unix.EINVAL)
	}
	family := binary.LittleEndian.Uint16(b[:2])
	switch family {
	case unix.AF_INET:
		if len(b) < 8 {
			return policy.SockTarget{}, fmt.Errorf("sockaddr_in of %d bytes: %w", len(b), unix.EINVAL)
		}
		return policy.SockTarget{Family: "inet", Port: int(binary.BigEndian.Uint16(b[2:4])),
			IP: net.IPv4(b[4], b[5], b[6], b[7]).To4()}, nil
	case unix.AF_INET6:
		if len(b) < 24 {
			return policy.SockTarget{}, fmt.Errorf("sockaddr_in6 of %d bytes: %w", len(b), unix.EINVAL)
		}
		ip := make(net.IP, 16)
		copy(ip, b[8:24])
		return policy.SockTarget{Family: "inet6", Port: int(binary.BigEndian.Uint16(b[2:4])), IP: ip}, nil
	case unix.AF_UNIX:
		if len(b) == 2 {
			return policy.SockTarget{Family: "unix"}, nil
		}
		path := b[2:]
		if path[0] == 0 {
			return policy.SockTarget{Family: "abstract", Path: string(bytes.TrimRight(path[1:], "\x00"))}, nil
		}
		if i := bytes.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		return policy.SockTarget{Family: "unix", Path: string(path)}, nil
	}
	return policy.SockTarget{Family: "other"}, nil
}
