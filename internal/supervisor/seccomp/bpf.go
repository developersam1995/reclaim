package seccomp

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

// fallThrough as a jump target continues with the next instruction.
const fallThrough = ""

// bpfClassMask extracts an opcode's instruction class (BPF_CLASS in C).
const bpfClassMask = 0x07

// bpfProgram is a tiny classic-BPF assembler with symbolic jump targets.
// Classic BPF only jumps forward, and a conditional jump reaches at most 255
// instructions ahead; assemble resolves labels and enforces both, plus the
// kernel's program-length limit and its rule that the program end in RET.
//
// It emits only instructions the kernel's seccomp action cache can emulate
// (LD W ABS, JEQ/JGE/JSET with K, RET K), so syscalls that the filter always
// allows skip the filter entirely after the first evaluation.
type bpfProgram struct {
	insns  []bpfInsn
	labels map[string]int // label → index of the instruction it precedes
	err    error          // first definition error, reported by assemble
}

// bpfInsn is an instruction whose jump targets are still symbolic.
type bpfInsn struct {
	code   uint16
	k      uint32
	jt, jf string // conditional jumps only; fallThrough continues
}

// label names the position of the next emitted instruction.
func (p *bpfProgram) label(name string) {
	if p.labels == nil {
		p.labels = make(map[string]int)
	}
	switch _, dup := p.labels[name]; {
	case name == fallThrough:
		p.fail(errors.New("bpf: empty label name"))
	case dup:
		p.fail(fmt.Errorf("bpf: label %q defined twice", name))
	default:
		p.labels[name] = len(p.insns)
	}
}

// loadWord loads the 32-bit word at offset in struct seccomp_data into A.
func (p *bpfProgram) loadWord(offset uint32) {
	p.insns = append(p.insns, bpfInsn{code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, k: offset})
}

// jumpIfEqual jumps to jt when A == k, else to jf.
func (p *bpfProgram) jumpIfEqual(k uint32, jt, jf string) {
	p.insns = append(p.insns, bpfInsn{code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, k: k, jt: jt, jf: jf})
}

// jumpIfAtLeast jumps to jt when A >= k (unsigned), else to jf.
func (p *bpfProgram) jumpIfAtLeast(k uint32, jt, jf string) {
	p.insns = append(p.insns, bpfInsn{code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, k: k, jt: jt, jf: jf})
}

// jumpIfAnySet jumps to jt when A & mask != 0, else to jf.
func (p *bpfProgram) jumpIfAnySet(mask uint32, jt, jf string) {
	p.insns = append(p.insns, bpfInsn{code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, k: mask, jt: jt, jf: jf})
}

// ret ends the program with the seccomp action k.
func (p *bpfProgram) ret(k uint32) {
	p.insns = append(p.insns, bpfInsn{code: unix.BPF_RET | unix.BPF_K, k: k})
}

func (p *bpfProgram) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

// assemble resolves every label and returns the program in kernel form.
func (p *bpfProgram) assemble() ([]unix.SockFilter, error) {
	if p.err != nil {
		return nil, p.err
	}
	n := len(p.insns)
	switch {
	case n == 0:
		return nil, errors.New("bpf: empty program")
	case n > unix.BPF_MAXINSNS:
		return nil, fmt.Errorf("bpf: program has %d instructions, the kernel accepts at most %d", n, unix.BPF_MAXINSNS)
	case p.insns[n-1].code&bpfClassMask != unix.BPF_RET:
		return nil, fmt.Errorf("bpf: last instruction (%d) is not a return", n-1)
	}
	out := make([]unix.SockFilter, n)
	for i, in := range p.insns {
		jt, err := p.jumpOffset(i, in.jt)
		if err != nil {
			return nil, err
		}
		jf, err := p.jumpOffset(i, in.jf)
		if err != nil {
			return nil, err
		}
		out[i] = unix.SockFilter{Code: in.code, Jt: jt, Jf: jf, K: in.k}
	}
	return out, nil
}

// jumpOffset converts the jump from instruction from to target into the
// relative offset classic BPF encodes (0 = the next instruction).
func (p *bpfProgram) jumpOffset(from int, target string) (uint8, error) {
	if target == fallThrough {
		return 0, nil
	}
	to, ok := p.labels[target]
	switch {
	case !ok:
		return 0, fmt.Errorf("bpf: instruction %d jumps to undefined label %q", from, target)
	case to >= len(p.insns):
		return 0, fmt.Errorf("bpf: instruction %d jumps to label %q, which is past the last instruction", from, target)
	case to <= from:
		return 0, fmt.Errorf("bpf: instruction %d jumps backwards to label %q (classic BPF only jumps forward)", from, target)
	}
	offset := to - from - 1
	if offset > math.MaxUint8 {
		return 0, fmt.Errorf("bpf: instruction %d jumps %d instructions ahead to label %q; conditional jumps reach at most %d",
			from, offset, target, math.MaxUint8)
	}
	return uint8(offset), nil
}
