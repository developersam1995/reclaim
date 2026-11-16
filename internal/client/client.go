// Package client connects to the Reclaim daemon: dialing (with optional
// auto-start), the hello handshake, request/response correlation, and server
// pushes.
package client

import (
	"context"
	"time"

	"reclaim/internal/config"
	"reclaim/internal/protocol"
)

// Conn is a connection to the daemon. Safe for concurrent use.
type Conn struct{ impl *connImpl }

// RemoteError is a TypeError response from the daemon.
type RemoteError struct{ Message string }

func (e *RemoteError) Error() string { return e.Message }

// Dial connects to socket and performs the hello handshake. The returned Conn
// reads in a background goroutine: responses (ID != 0) are routed to their
// waiters, pushes (ID 0) are delivered on Pushes().
func Dial(socket string, hello protocol.Hello) (*Conn, protocol.Welcome, error) {
	impl, w, err := dial(socket, hello)
	if err != nil {
		return nil, w, err
	}
	return &Conn{impl: impl}, w, nil
}

// EnsureDaemon makes sure a daemon is accepting connections on paths.Socket.
// If not, it starts `exe daemon` detached (new session via setsid, stdin
// /dev/null, stdout+stderr appended to paths.DaemonLog, environment inherited)
// and waits up to timeout for the socket to accept. Returns started=true if
// it launched a daemon.
func EnsureDaemon(paths config.Paths, exe string, timeout time.Duration) (started bool, err error) {
	return ensureDaemon(paths, exe, timeout)
}

// Start sends a request and returns its envelope ID and a channel that will
// receive exactly one response envelope (or be closed without a value if the
// connection drops or Forget is called).
func (c *Conn) Start(typ string, body any) (uint64, <-chan protocol.Envelope, error) {
	return c.impl.start(typ, body)
}

// Forget stops waiting for the response to id (its channel is closed).
func (c *Conn) Forget(id uint64) { c.impl.forget(id) }

// Call sends a request and waits for its response or ctx. A TypeError response
// is returned as *RemoteError. If out is non-nil the response body is decoded
// into it.
func (c *Conn) Call(ctx context.Context, typ string, body any, out any) error {
	return c.impl.call(ctx, typ, body, out)
}

// Send writes a message that expects no response (ID 0).
func (c *Conn) Send(typ string, body any) error { return c.impl.send(typ, body) }

// Pushes delivers server pushes (ID 0). Buffered (256); closed on disconnect.
// If the buffer is full the oldest pending push is dropped, never blocking the
// reader.
func (c *Conn) Pushes() <-chan protocol.Envelope { return c.impl.pushes() }

// Done is closed when the connection is lost or closed.
func (c *Conn) Done() <-chan struct{} { return c.impl.done() }

// Err returns why the connection ended (nil while open).
func (c *Conn) Err() error { return c.impl.err() }

// Close closes the connection.
func (c *Conn) Close() error { return c.impl.close() }
