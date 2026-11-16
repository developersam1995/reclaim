package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"reclaim/internal/protocol"
)

const (
	// helloID is the envelope ID of the handshake. Start numbers requests
	// after it, so no response can be mistaken for the welcome.
	helloID uint64 = 1

	// pushBuffer is the capacity of the Pushes channel.
	pushBuffer = 256

	// maxQuotedBody bounds how much of an undecodable error body is quoted
	// in the resulting RemoteError.
	maxQuotedBody = 200
)

// timeouts bounds the client's blocking I/O.
type timeouts struct {
	dial      time.Duration // connecting to the socket
	handshake time.Duration // sending hello and receiving the welcome
	write     time.Duration // each envelope written after the handshake
}

// defaultTimeouts are the limits Dial uses. A write that cannot finish
// within the write timeout means the daemon stopped reading; the connection
// is then dropped instead of blocking the caller (and, in a session, the
// paused agent thread) indefinitely.
var defaultTimeouts = timeouts{
	dial:      2 * time.Second,
	handshake: 5 * time.Second,
	write:     10 * time.Second,
}

// Reasons a connection ended, as reported by Err.
var (
	// errClientClosed means Close was called; it wraps net.ErrClosed.
	errClientClosed = fmt.Errorf("connection closed by client: %w", net.ErrClosed)
	// errDaemonHungUp means the daemon closed its end; it wraps io.EOF.
	errDaemonHungUp = fmt.Errorf("daemon closed the connection: %w", io.EOF)
)

// errEmptyType rejects a message without a type before anything is sent.
var errEmptyType = errors.New("reclaim client: message type is empty")

// connImpl is the state behind Conn.
//
// A single reader goroutine owns the receive side. It hands each response
// to the waiter registered for its ID and queues pushes, never blocking on
// a consumer. When it stops (daemon hang-up, read error, Close, or a failed
// write that aborted the stream) it records why, closes every pending waiter
// channel without a value, closes Pushes, and finally closes Done.
type connImpl struct {
	nc    net.Conn
	codec *protocol.Codec

	// writeTimeout (nanoseconds) bounds each write once the handshake is
	// done. It is zero during the handshake, which has its own deadline.
	writeTimeout atomic.Int64
	// lastID is the most recently issued request ID.
	lastID atomic.Uint64

	closeOnce sync.Once // closes nc exactly once

	mu          sync.Mutex
	waiters     map[uint64]chan protocol.Envelope // pending requests; nil once the connection has ended
	closeReason error                             // why nc was closed; the first cause wins
	endErr      error                             // why the connection ended; nil while open

	pushCh chan protocol.Envelope
	doneCh chan struct{}
}

func newConnImpl(nc net.Conn) *connImpl {
	c := &connImpl{
		nc:      nc,
		waiters: make(map[uint64]chan protocol.Envelope),
		pushCh:  make(chan protocol.Envelope, pushBuffer),
		doneCh:  make(chan struct{}),
	}
	c.codec = protocol.NewCodec(connIO{c})
	c.lastID.Store(helloID)
	return c
}

// dial connects with the default timeouts.
func dial(socket string, hello protocol.Hello) (*connImpl, protocol.Welcome, error) {
	return dialWith(socket, hello, defaultTimeouts)
}

// dialWith connects to socket, completes the hello handshake, and starts the
// reader. A zero hello.Version is sent as protocol.Version. On failure the
// socket is closed and the returned Welcome is zero.
func dialWith(socket string, hello protocol.Hello, to timeouts) (*connImpl, protocol.Welcome, error) {
	if socket == "" {
		return nil, protocol.Welcome{}, errors.New("connect to reclaim daemon: no socket path")
	}
	nc, err := net.DialTimeout("unix", socket, to.dial)
	if err != nil {
		return nil, protocol.Welcome{}, fmt.Errorf("connect to reclaim daemon: %w", err)
	}
	c := newConnImpl(nc)
	w, err := c.handshake(hello, to.handshake)
	if err != nil {
		_ = c.abort(err)
		return nil, protocol.Welcome{}, err
	}
	c.writeTimeout.Store(int64(to.write))
	go c.readLoop()
	return c, w, nil
}

// handshake sends hello with ID helloID and reads until the envelope
// answering it, all within timeout. Pushes arriving first are kept for
// Pushes; envelopes with other IDs answer nothing and are skipped.
func (c *connImpl) handshake(hello protocol.Hello, timeout time.Duration) (protocol.Welcome, error) {
	if hello.Version == 0 {
		hello.Version = protocol.Version
	}
	if err := c.nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		return protocol.Welcome{}, fmt.Errorf("reclaim daemon handshake: %w", err)
	}
	if err := c.codec.Write(protocol.TypeHello, helloID, hello); err != nil {
		return protocol.Welcome{}, fmt.Errorf("reclaim daemon handshake: send hello: %w", err)
	}
	for {
		env, err := c.codec.Read()
		if err != nil {
			return protocol.Welcome{}, handshakeReadError(err, timeout)
		}
		if env.ID == 0 {
			// The daemon has no reason to push before welcoming us, but a
			// push is never thrown away.
			c.enqueuePush(env)
			continue
		}
		if env.ID != helloID {
			continue
		}
		switch env.Type {
		case protocol.TypeWelcome:
			w, err := protocol.Decode[protocol.Welcome](env)
			if err != nil {
				return protocol.Welcome{}, fmt.Errorf("reclaim daemon handshake: malformed welcome: %w", err)
			}
			if err := c.nc.SetDeadline(time.Time{}); err != nil {
				return protocol.Welcome{}, fmt.Errorf("reclaim daemon handshake: clear deadline: %w", err)
			}
			return w, nil
		case protocol.TypeError:
			return protocol.Welcome{}, remoteError(env)
		default:
			return protocol.Welcome{}, fmt.Errorf("reclaim daemon handshake: got %q in reply to hello, want %q or %q",
				env.Type, protocol.TypeWelcome, protocol.TypeError)
		}
	}
}

// handshakeReadError explains a read that failed before the welcome.
func handshakeReadError(err error, timeout time.Duration) error {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("reclaim daemon handshake: no welcome within %s: %w", timeout, err)
	case errors.Is(err, io.EOF):
		return fmt.Errorf("reclaim daemon handshake: daemon closed the connection before welcoming: %w", err)
	default:
		return fmt.Errorf("reclaim daemon handshake: %w", err)
	}
}

// readLoop is the connection's only reader. It never blocks on consumers:
// each waiter channel has room for its single response, and pushes use
// drop-oldest queueing.
func (c *connImpl) readLoop() {
	for {
		env, err := c.codec.Read()
		if err != nil {
			c.finish(err)
			return
		}
		if env.ID == 0 {
			c.enqueuePush(env)
		} else {
			c.deliver(env)
		}
	}
}

// deliver hands a response to the waiter registered for its ID, then closes
// that channel: it receives exactly one envelope. Responses nobody waits for
// (forgotten requests, unsolicited IDs) are dropped.
func (c *connImpl) deliver(env protocol.Envelope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.waiters[env.ID]
	if !ok {
		return
	}
	delete(c.waiters, env.ID)
	ch <- env // capacity 1 and the only send: never blocks
	close(ch)
}

// enqueuePush queues a push without ever blocking: when the consumer has
// fallen pushBuffer pushes behind, the oldest queued push is dropped. Only
// one goroutine at a time sends on pushCh (the handshake, then the reader),
// so after one push is removed the next send finds room.
func (c *connImpl) enqueuePush(env protocol.Envelope) {
	for {
		select {
		case c.pushCh <- env:
			return
		default:
		}
		select {
		case <-c.pushCh:
		default:
		}
	}
}

// finish ends the connection after the reader's final read error.
func (c *connImpl) finish(readErr error) {
	// Close the socket even when the reader stopped on its own (hang-up,
	// malformed data): nothing more may be written to a stream nobody reads,
	// and the daemon must see the hang-up. If the socket was already closed,
	// the reason recorded then stands and readErr is merely its echo.
	_ = c.abort(readFailure(readErr))

	c.mu.Lock()
	c.endErr = c.closeReason
	waiters := c.waiters
	c.waiters = nil
	c.mu.Unlock()

	for _, ch := range waiters {
		close(ch)
	}
	close(c.pushCh)
	close(c.doneCh)
}

// readFailure turns the reader's final error into the reason Err reports.
func readFailure(err error) error {
	if errors.Is(err, io.EOF) {
		return errDaemonHungUp
	}
	return fmt.Errorf("receive from daemon: %w", err)
}

// abort closes the socket once, recording reason as why the connection
// ends; the reader then fails its pending read and calls finish. It returns
// the socket's Close error on the call that closed it, nil otherwise.
func (c *connImpl) abort(reason error) error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closeReason = reason
		c.mu.Unlock()
		err = c.nc.Close()
	})
	return err
}

// start registers a waiter for a fresh ID before writing the request, so a
// fast response cannot slip past it.
func (c *connImpl) start(typ string, body any) (uint64, <-chan protocol.Envelope, error) {
	if typ == "" {
		return 0, nil, errEmptyType
	}
	ch := make(chan protocol.Envelope, 1)
	c.mu.Lock()
	if c.waiters == nil {
		cause := c.endErr
		c.mu.Unlock()
		return 0, nil, connDownError(typ, cause)
	}
	id := c.lastID.Add(1)
	c.waiters[id] = ch
	c.mu.Unlock()

	if err := c.codec.Write(typ, id, body); err != nil {
		c.mu.Lock()
		delete(c.waiters, id) // no-op if the connection ended meanwhile
		c.mu.Unlock()
		return 0, nil, c.sendError(typ, err)
	}
	return id, ch, nil
}

// forget unregisters id and closes its channel. Unknown, already answered,
// and already forgotten IDs are ignored.
func (c *connImpl) forget(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.waiters[id]; ok {
		delete(c.waiters, id)
		close(ch)
	}
}

func (c *connImpl) call(ctx context.Context, typ string, body, out any) error {
	if ctx == nil {
		return errors.New("reclaim client: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err // nothing sent
	}
	id, ch, err := c.start(typ, body)
	if err != nil {
		return err
	}
	select {
	case env, ok := <-ch:
		if !ok {
			return c.lostError(typ)
		}
		return decodeResponse(typ, env, out)
	case <-ctx.Done():
		c.forget(id)
		return ctx.Err()
	}
}

// decodeResponse turns a response envelope into Call's result.
func decodeResponse(reqType string, env protocol.Envelope, out any) error {
	if env.Type == protocol.TypeError {
		return remoteError(env)
	}
	if out == nil || len(env.Body) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Body, out); err != nil {
		return fmt.Errorf("decode %q response to %q: %w", env.Type, reqType, err)
	}
	return nil
}

// remoteError converts a TypeError envelope. A body that does not decode
// still yields a RemoteError (the daemon did refuse), quoting the body.
func remoteError(env protocol.Envelope) *RemoteError {
	e, err := protocol.Decode[protocol.Error](env)
	switch {
	case err != nil:
		return &RemoteError{Message: "reclaim daemon sent a malformed error: " + truncate(string(env.Body), maxQuotedBody)}
	case strings.TrimSpace(e.Message) == "":
		return &RemoteError{Message: "reclaim daemon reported an error without a message"}
	}
	return &RemoteError{Message: e.Message}
}

func (c *connImpl) send(typ string, body any) error {
	if typ == "" {
		return errEmptyType
	}
	if cause := c.err(); cause != nil {
		return connDownError(typ, cause)
	}
	if err := c.codec.Write(typ, 0, body); err != nil {
		return c.sendError(typ, err)
	}
	return nil
}

// sendError describes a failed write of a typ message, preferring the reason
// the connection ended when the failure is a consequence of it.
func (c *connImpl) sendError(typ string, err error) error {
	if cause := c.err(); cause != nil {
		return connDownError(typ, cause)
	}
	return fmt.Errorf("send %q to reclaim daemon: %w", typ, err)
}

// connDownError reports a message that cannot be sent because the
// connection has ended.
func connDownError(typ string, cause error) error {
	return fmt.Errorf("send %q: connection to reclaim daemon has ended: %w", typ, cause)
}

// lostError explains a response channel that closed without a value.
func (c *connImpl) lostError(typ string) error {
	cause := c.err()
	switch {
	case cause == nil:
		// On a live connection only Forget closes a waiter.
		return fmt.Errorf("%q request was forgotten before the reclaim daemon answered", typ)
	case errors.Is(cause, errClientClosed):
		return fmt.Errorf("connection closed before the reclaim daemon answered %q: %w", typ, cause)
	default:
		return fmt.Errorf("reclaim daemon disconnected before answering %q: %w", typ, cause)
	}
}

func (c *connImpl) pushes() <-chan protocol.Envelope { return c.pushCh }

func (c *connImpl) done() <-chan struct{} { return c.doneCh }

func (c *connImpl) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endErr
}

// close closes the socket and waits for the reader to finish, so Done,
// Err, Pushes and pending waiters all reflect the closed connection when it
// returns. Later calls return nil.
func (c *connImpl) close() error {
	err := c.abort(errClientClosed)
	<-c.doneCh
	if err != nil {
		return fmt.Errorf("close reclaim daemon connection: %w", err)
	}
	return nil
}

// connIO is the stream under the codec. Reads pass straight through. Writes
// are where the codec's whole encoded line arrives in one call, so this is
// where oversized lines are refused before any byte is sent, each write
// after the handshake gets a deadline, and any failed write aborts the
// connection, since a partially written line would corrupt the stream.
type connIO struct{ c *connImpl }

func (w connIO) Read(p []byte) (int, error) { return w.c.nc.Read(p) }

func (w connIO) Write(p []byte) (int, error) {
	if len(p) > protocol.MaxLine {
		return 0, fmt.Errorf("message of %d bytes exceeds the %d-byte protocol limit", len(p), protocol.MaxLine)
	}
	if d := time.Duration(w.c.writeTimeout.Load()); d > 0 {
		if err := w.c.nc.SetWriteDeadline(time.Now().Add(d)); err != nil {
			return 0, err // only fails on a closed socket
		}
	}
	n, err := w.c.nc.Write(p)
	if err != nil {
		_ = w.c.abort(fmt.Errorf("send to daemon: %w", err))
	}
	return n, err
}

// truncate cuts s to at most limit bytes on a rune boundary, marking the cut.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
