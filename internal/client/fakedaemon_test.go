package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"reclaim/internal/protocol"
)

// testTimeout bounds every wait in these tests, so a bug fails fast instead
// of hanging the suite.
const testTimeout = 5 * time.Second

// shortTempDir returns a fresh temporary directory with a short path: unix
// socket paths are limited to 108 bytes.
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := ""
	if len(os.TempDir()) > 40 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "rc")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeDaemon is a scripted stand-in for the reclaim daemon: it listens on a
// temporary socket and hands each accepted connection to the test, which
// plays the daemon's side with a protocol.Codec.
type fakeDaemon struct {
	t     *testing.T
	path  string
	peers chan *peer
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	d := &fakeDaemon{t: t, path: path, peers: make(chan *peer)}
	quit := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case d.peers <- &peer{t: t, nc: nc, codec: protocol.NewCodec(nc)}:
			case <-quit:
				_ = nc.Close()
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(quit)
		_ = ln.Close()
		<-stopped
	})
	return d
}

// accept returns the daemon side of the next client connection.
func (d *fakeDaemon) accept() *peer {
	d.t.Helper()
	select {
	case p := <-d.peers:
		d.t.Cleanup(func() { _ = p.nc.Close() })
		return p
	case <-time.After(testTimeout):
		d.t.Fatal("daemon: no client connected")
		return nil
	}
}

// peer is the daemon side of one connection. Its methods fail the test, so
// they must run on the test goroutine.
type peer struct {
	t     *testing.T
	nc    net.Conn
	codec *protocol.Codec
}

// read returns the next envelope the client sent.
func (p *peer) read() protocol.Envelope {
	p.t.Helper()
	if err := p.nc.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		p.t.Fatalf("daemon: set read deadline: %v", err)
	}
	env, err := p.codec.Read()
	if err != nil {
		p.t.Fatalf("daemon: read: %v", err)
	}
	return env
}

// write sends an envelope to the client.
func (p *peer) write(typ string, id uint64, body any) {
	p.t.Helper()
	if err := p.codec.Write(typ, id, body); err != nil {
		p.t.Fatalf("daemon: write %s: %v", typ, err)
	}
}

// writeRaw sends line plus a newline, bypassing the codec.
func (p *peer) writeRaw(line string) {
	p.t.Helper()
	if _, err := io.WriteString(p.nc, line+"\n"); err != nil {
		p.t.Fatalf("daemon: write raw line: %v", err)
	}
}

// expectHello reads the client's first message and checks it is a hello
// with the handshake ID.
func (p *peer) expectHello() protocol.Hello {
	p.t.Helper()
	env := p.read()
	if env.Type != protocol.TypeHello || env.ID != helloID {
		p.t.Fatalf("daemon: first message is %q #%d, want %q #%d", env.Type, env.ID, protocol.TypeHello, helloID)
	}
	h, err := protocol.Decode[protocol.Hello](env)
	if err != nil {
		p.t.Fatalf("daemon: %v", err)
	}
	return h
}

// expectHangup asserts the client closes its end without sending anything
// more.
func (p *peer) expectHangup() {
	p.t.Helper()
	if err := p.nc.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		p.t.Fatalf("daemon: set read deadline: %v", err)
	}
	env, err := p.codec.Read()
	switch {
	case err == nil:
		p.t.Fatalf("daemon: got %q #%d, want the client to hang up", env.Type, env.ID)
	case errors.Is(err, io.EOF), errors.Is(err, syscall.ECONNRESET):
	default:
		p.t.Fatalf("daemon: read: %v, want the client to hang up", err)
	}
}

// dialResult carries Dial's results out of a goroutine.
type dialResult struct {
	conn *Conn
	w    protocol.Welcome
	err  error
}

// dialAsync dials in a goroutine, since Dial blocks until the fake daemon
// (driven by the test goroutine) answers. A nil to uses the exported Dial
// with its default timeouts.
func dialAsync(socket string, hello protocol.Hello, to *timeouts) <-chan dialResult {
	ch := make(chan dialResult, 1)
	go func() {
		if to == nil {
			c, w, err := Dial(socket, hello)
			ch <- dialResult{c, w, err}
			return
		}
		impl, w, err := dialWith(socket, hello, *to)
		var c *Conn
		if impl != nil {
			c = &Conn{impl: impl}
		}
		ch <- dialResult{c, w, err}
	}()
	return ch
}

// connect dials the fake daemon with the default timeouts and completes the
// handshake, returning the client and the daemon side of the connection.
func connect(t *testing.T, d *fakeDaemon) (*Conn, *peer) {
	t.Helper()
	return connectWith(t, d, nil)
}

// connectWith is connect with explicit timeouts (nil means the defaults).
func connectWith(t *testing.T, d *fakeDaemon, to *timeouts) (*Conn, *peer) {
	t.Helper()
	res := dialAsync(d.path, protocol.Hello{Role: protocol.RoleCLI}, to)
	p := d.accept()
	p.expectHello()
	p.write(protocol.TypeWelcome, helloID, protocol.Welcome{Version: protocol.Version, DaemonPID: 4242})
	r := recv(t, res, "Dial")
	if r.err != nil {
		t.Fatalf("Dial: %v", r.err)
	}
	t.Cleanup(func() { _ = r.conn.Close() })
	return r.conn, p
}

// callAsync runs c.Call in a goroutine and returns its eventual error.
func callAsync(ctx context.Context, c *Conn, typ string, body, out any) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- c.Call(ctx, typ, body, out) }()
	return ch
}

// roundTrip proves the connection still works: the next message the daemon
// sees is a fresh "ping" request, and its answer reaches the caller.
func roundTrip(t *testing.T, c *Conn, p *peer) {
	t.Helper()
	var ok protocol.OK
	errc := callAsync(context.Background(), c, "ping", nil, &ok)
	req := p.read()
	if req.Type != "ping" {
		t.Fatalf("daemon got %q #%d, want the ping request", req.Type, req.ID)
	}
	p.write(protocol.TypeOK, req.ID, protocol.OK{Message: "pong"})
	if err := recv(t, errc, "ping Call"); err != nil {
		t.Fatalf("ping Call: %v", err)
	}
	if ok.Message != "pong" {
		t.Fatalf("ping answer = %q, want %q", ok.Message, "pong")
	}
}

// recv receives a value from ch, failing the test if none arrives in time.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// waitClosed asserts ch gets closed (without delivering a value) in time.
func waitClosed[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("%s delivered a value, want it closed", what)
		}
	case <-time.After(testTimeout):
		t.Fatalf("%s was not closed", what)
	}
}

// pendingWaiters reports how many requests are registered on c.
func pendingWaiters(c *Conn) int {
	c.impl.mu.Lock()
	defer c.impl.mu.Unlock()
	return len(c.impl.waiters)
}
