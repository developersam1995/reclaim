package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"reclaim/internal/config"
	"reclaim/internal/protocol"
)

func TestHandshake(t *testing.T) {
	d := newFakeDaemon(t)
	c, p := connect(t, d)
	roundTrip(t, c, p)

	// TypeError in reply to hello.
	res := dialAsync(d.path, protocol.Hello{Role: protocol.RoleCLI}, nil)
	p2 := d.accept()
	p2.expectHello()
	p2.write(protocol.TypeError, helloID, protocol.Error{Message: "nope"})
	r := recv(t, res, "Dial")
	var re *RemoteError
	if !errors.As(r.err, &re) || re.Message != "nope" {
		t.Fatalf("Dial error = %v, want RemoteError nope", r.err)
	}
	// Wrong reply type.
	res = dialAsync(d.path, protocol.Hello{Role: protocol.RoleCLI}, nil)
	p3 := d.accept()
	p3.expectHello()
	p3.write(protocol.TypeOK, helloID, nil)
	if r := recv(t, res, "Dial"); r.err == nil {
		t.Fatal("expected error for wrong reply type")
	}
	// Handshake timeout.
	to := defaultTimeouts
	to.handshake = 200 * time.Millisecond
	res = dialAsync(d.path, protocol.Hello{Role: protocol.RoleCLI}, &to)
	p4 := d.accept()
	p4.expectHello()
	if r := recv(t, res, "Dial"); r.err == nil || !errors.Is(r.err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", r.err)
	}
}

func TestCallsConcurrentAndOutOfOrder(t *testing.T) {
	d := newFakeDaemon(t)
	c, p := connect(t, d)
	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	outs := make([]protocol.OK, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.Call(context.Background(), "ping", map[string]int{"i": i}, &outs[i])
		}(i)
	}
	var reqs []protocol.Envelope
	for i := 0; i < n; i++ {
		reqs = append(reqs, p.read())
	}
	for i := len(reqs) - 1; i >= 0; i-- { // answer in reverse order
		var body struct{ I int }
		_ = protocol.Decode[struct{ I int }]
		b, _ := protocol.Decode[map[string]int](reqs[i])
		body.I = b["i"]
		p.write(protocol.TypeOK, reqs[i].ID, protocol.OK{Message: strings.Repeat("x", body.I)})
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil || len(outs[i].Message) != i {
			t.Fatalf("call %d: err=%v msg=%q", i, errs[i], outs[i].Message)
		}
	}
	if pendingWaiters(c) != 0 {
		t.Fatal("waiters leaked")
	}
}

func TestCallRemoteErrorAndCancel(t *testing.T) {
	d := newFakeDaemon(t)
	c, p := connect(t, d)
	errc := callAsync(context.Background(), c, "x", nil, nil)
	req := p.read()
	p.write(protocol.TypeError, req.ID, protocol.Error{Message: "bad"})
	var re *RemoteError
	if err := recv(t, errc, "call"); !errors.As(err, &re) || re.Message != "bad" {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc = callAsync(ctx, c, "y", nil, nil)
	p.read()
	cancel()
	if err := recv(t, errc, "cancelled call"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if pendingWaiters(c) != 0 {
		t.Fatal("cancelled waiter leaked")
	}
	roundTrip(t, c, p)
}

func TestPushesAndDisconnect(t *testing.T) {
	d := newFakeDaemon(t)
	c, p := connect(t, d)
	for i := 0; i < pushBuffer+10; i++ {
		p.write(protocol.TypeState, 0, map[string]int{"n": i})
	}
	// A round trip after the pushes guarantees the reader has enqueued them all.
	roundTrip(t, c, p)
	first := <-c.Pushes()
	b, _ := protocol.Decode[map[string]int](first)
	if b["n"] != 10 {
		t.Fatalf("oldest retained push = %d, want 10 (drop-oldest)", b["n"])
	}
	errc := callAsync(context.Background(), c, "z", nil, nil)
	p.read()
	p.nc.Close()
	if err := recv(t, errc, "call after hangup"); err == nil {
		t.Fatal("pending call should fail on hangup")
	}
	select {
	case <-c.Done():
	case <-time.After(testTimeout):
		t.Fatal("Done not closed")
	}
	if c.Err() == nil {
		t.Fatal("Err nil after hangup")
	}
	for range c.Pushes() {
	} // closed
	if err := c.Send("touch", nil); err == nil {
		t.Fatal("send on dead connection should fail")
	}
}

func TestSendAndForget(t *testing.T) {
	d := newFakeDaemon(t)
	c, p := connect(t, d)
	if err := c.Send(protocol.TypeTouch, protocol.Touch{AgentID: "a"}); err != nil {
		t.Fatal(err)
	}
	env := p.read()
	if env.Type != protocol.TypeTouch || env.ID != 0 {
		t.Fatalf("send = %+v", env)
	}
	id, ch, err := c.Start("q", nil)
	if err != nil {
		t.Fatal(err)
	}
	p.read()
	c.Forget(id)
	waitClosed(t, ch, "forgotten channel")
	c.Forget(id) // idempotent
	roundTrip(t, c, p)
}

func TestEnsureDaemon(t *testing.T) {
	d := newFakeDaemon(t)
	paths := config.Paths{Socket: d.path, DaemonLog: filepath.Join(t.TempDir(), "log"), StateDir: t.TempDir(), RuntimeDir: t.TempDir()}
	started, err := EnsureDaemon(paths, "/nonexistent", time.Second)
	if err != nil || started {
		t.Fatalf("existing daemon: %v %v", started, err)
	}
	// Nothing listening; the exe script starts a listener.
	dir := shortTempDir(t)
	paths.Socket = filepath.Join(dir, "n.sock")
	exe := filepath.Join(dir, "fake.sh")
	script := "#!/bin/sh\n[ \"$1\" = daemon ] || exit 9\necho starting\nexec python3 -c 'import socket,sys,time\ns=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(5)\nwhile True: c,_=s.accept(); c.close()' " + paths.Socket + "\n"
	os.WriteFile(exe, []byte(script), 0o755)
	started, err = EnsureDaemon(paths, exe, 5*time.Second)
	if err != nil || !started {
		t.Fatalf("start: %v %v", started, err)
	}
	// Timeout case: script exits immediately after logging.
	paths.Socket = filepath.Join(dir, "t.sock")
	os.WriteFile(exe, []byte("#!/bin/sh\necho boom-log-line\nexit 1\n"), 0o755)
	_, err = EnsureDaemon(paths, exe, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "boom-log-line") {
		t.Fatalf("timeout error = %v", err)
	}
}
