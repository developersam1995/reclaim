// Package protocol defines the JSON-lines wire protocol spoken over the
// daemon's Unix socket by sessions (`reclaim run`), the console UI, and CLI
// commands.
//
// Framing: one JSON Envelope per line ('\n'-terminated), max MaxLine bytes.
// Requests carry a non-zero client-chosen ID; the daemon's response echoes it.
// Server pushes (lease updates, state snapshots) carry ID 0.
//
// Every connection starts with the client sending TypeHello and the daemon
// replying TypeWelcome (or TypeError) with the same ID.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Version is bumped on incompatible protocol changes.
const Version = 1

// MaxLine bounds a single encoded envelope.
const MaxLine = 4 << 20

// Message types. Direction and body type are noted per constant.
const (
	TypeHello   = "hello"   // client -> daemon, request.  Body: Hello.         Response: TypeWelcome
	TypeWelcome = "welcome" // daemon -> client, response. Body: Welcome
	TypeOK      = "ok"      // daemon -> client, response. Body: OK
	TypeError   = "error"   // daemon -> client, response. Body: Error

	// Session (role "session") traffic.
	TypeAccess   = "access"   // session -> daemon, request. Body: AccessRequest. Response: TypeDecision (may take up to the prompt timeout)
	TypeDecision = "decision" // daemon -> session, response. Body: Decision
	TypeCancel   = "cancel"   // session -> daemon, no response. Body: Cancel (the paused process died; drop its prompt waiter)
	TypeTouch    = "touch"    // session -> daemon, no response. Body: Touch (batched lease usage, at most every 500ms)
	TypeEvent    = "event"    // session -> daemon, no response. Body: SessionEvent (audit-worthy session-side events)
	TypeLease    = "lease"    // daemon -> session, push.    Body: LeaseUpdate (lease opened/changed/closed for the session's agent)

	TypeStopping = "stopping" // daemon -> all clients, push, before shutdown. Body: none (sessions must not auto-start a daemon for 5s)

	// Console / CLI traffic.
	TypeStatus        = "status"         // client -> daemon, request. Body: none. Response: TypeState
	TypeState         = "state"          // daemon -> client, response or push. Body: State
	TypeSubscribe     = "subscribe"      // ui -> daemon, request. Response: TypeOK, then TypeState pushes on every change (debounced) and at least every second
	TypeAnswer        = "answer"         // ui/cli -> daemon, request. Body: Answer. Response: TypeOK or TypeError (e.g. wrong challenge)
	TypeReclaim       = "reclaim"        // cli -> daemon, request. Body: ReclaimRequest. Response: TypeReclaimResult
	TypeReclaimResult = "reclaim_result" // daemon -> cli, response. Body: ReclaimResult
	TypeHold          = "hold"           // cli -> daemon, request. Body: HoldRequest. Response: TypeOK or TypeError
	TypeSetTTL        = "set_ttl"        // cli -> daemon, request. Body: SetTTLRequest. Response: TypeOK or TypeError
	TypeAudit         = "audit"          // cli -> daemon, request. Body: AuditQuery. Response: TypeAuditResult
	TypeAuditResult   = "audit_result"   // daemon -> cli, response. Body: AuditResult
	TypeShutdown      = "shutdown"       // cli -> daemon, request. Body: none. Response: TypeOK, then the daemon exits
)

// Client roles sent in Hello.
const (
	RoleSession = "session" // a `reclaim run` launcher supervising one agent session
	RoleUI      = "ui"      // the interactive console
	RoleCLI     = "cli"     // one-shot CLI commands
)

// Envelope is one framed message.
type Envelope struct {
	Type string          `json:"type"`
	ID   uint64          `json:"id,omitempty"`
	Body json.RawMessage `json:"body,omitempty"`
}

// Decode unmarshals an envelope body into T.
func Decode[T any](e Envelope) (T, error) {
	var v T
	if len(e.Body) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(e.Body, &v); err != nil {
		return v, fmt.Errorf("decode %s body: %w", e.Type, err)
	}
	return v, nil
}

// Codec reads and writes envelopes on a stream. Write is safe for concurrent
// use; Read must be called from a single goroutine.
type Codec struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

// NewCodec wraps rw.
func NewCodec(rw io.ReadWriter) *Codec {
	return &Codec{r: bufio.NewReaderSize(rw, 64<<10), w: rw}
}

// ErrLineTooLong is returned when a peer sends an oversized envelope.
var ErrLineTooLong = errors.New("protocol: envelope exceeds MaxLine")

// Read returns the next envelope.
func (c *Codec) Read() (Envelope, error) {
	var buf []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxLine {
			return Envelope{}, ErrLineTooLong
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(strings.TrimSpace(string(buf))) > 0 {
			break
		}
		return Envelope{}, err
	}
	var e Envelope
	if err := json.Unmarshal(buf, &e); err != nil {
		return Envelope{}, fmt.Errorf("protocol: bad envelope: %w", err)
	}
	return e, nil
}

// Write encodes body (may be nil) as an envelope of the given type and ID.
func (c *Codec) Write(typ string, id uint64, body any) error {
	e := Envelope{Type: typ, ID: id}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("protocol: encode %s: %w", typ, err)
		}
		e.Body = b
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.w.Write(line)
	return err
}

// Duration is a time.Duration that encodes as a Go duration string ("15m0s")
// and decodes from either a duration string or integer nanoseconds.
type Duration time.Duration

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration: want string or integer nanoseconds: %w", err)
	}
	*d = Duration(n)
	return nil
}

// Hello is the first message on every connection.
type Hello struct {
	Role    string       `json:"role"`
	Version int          `json:"version"`
	Session *SessionInfo `json:"session,omitempty"` // required when Role == RoleSession
	// Resume is the SessionID of a session re-connecting after the daemon
	// restarted or the connection dropped: the daemon re-registers it without
	// a launch grant or a session_start audit event, and the Welcome replaces
	// the session's whole lease cache.
	Resume string `json:"resume,omitempty"`
}

// Welcome answers Hello.
type Welcome struct {
	Version       int                   `json:"version"`
	DaemonPID     int                   `json:"daemon_pid"`
	SessionID     string                `json:"session_id,omitempty"` // assigned for RoleSession
	Policies      map[string]PolicyInfo `json:"policies"`             // keyed by space name
	Leases        []LeaseInfo           `json:"leases"`               // RoleSession: currently open leases of the session's agent
	PromptTimeout Duration              `json:"prompt_timeout"`
}

// OK is an empty success response. Message is optional human text.
type OK struct {
	Message string `json:"message,omitempty"`
}

// Error is a failure response.
type Error struct {
	Message string `json:"message"`
}

// SessionInfo describes one supervised agent session.
type SessionInfo struct {
	ID           string    `json:"id"`           // assigned by the daemon
	Agent        string    `json:"agent"`        // display name, e.g. "claude"
	AgentID      string    `json:"agent_id"`     // lease identity: Agent + "@" + primary project root
	Projects     []string  `json:"projects"`     // absolute project roots
	Command      []string  `json:"command"`      // argv of the agent
	Cwd          string    `json:"cwd"`          // launch directory
	LauncherPID  int       `json:"launcher_pid"` // pid of `reclaim run` (the supervisor)
	AgentPID     int       `json:"agent_pid"`    // pid of the agent root process
	StartedAt    time.Time `json:"started_at"`
	CurrentSpace string    `json:"current_space,omitempty"` // where the agent is working now (from touches)
	Observe      bool      `json:"observe,omitempty"`       // observe mode: gated accesses are reported, never prompted
}

// PolicyInfo is the wire form of space.Policy.
type PolicyInfo struct {
	Kind          string   `json:"kind"` // "sliding" | "fixed"
	TTL           Duration `json:"ttl"`
	Friction      string   `json:"friction"` // "low" | "medium" | "high"
	GatedOps      []string `json:"gated_ops"`
	AllowOnce     bool     `json:"allow_once"`
	GrantOnLaunch bool     `json:"grant_on_launch,omitempty"`
}

// Lease sources.
const (
	SourceLaunch = "launch" // opened automatically when a session started (Project Space)
	SourcePrompt = "prompt" // user approved a prompt
	SourceHold   = "hold"   // manual `reclaim hold`
)

// LeaseInfo is the wire form of an open lease.
type LeaseInfo struct {
	AgentID   string    `json:"agent_id"`
	Agent     string    `json:"agent"`
	Space     string    `json:"space"`
	Kind      string    `json:"kind"`   // "sliding" | "fixed"
	Source    string    `json:"source"` // SourceLaunch | SourcePrompt | SourceHold
	GrantedAt time.Time `json:"granted_at"`
	LastUsed  time.Time `json:"last_used"`
	TTL       Duration  `json:"ttl"`                  // idle window (sliding) or lifetime (fixed)
	ExpiresAt time.Time `json:"expires_at"`           // as of the daemon's last computation: max(policy expiry, HoldUntil)
	HoldUntil time.Time `json:"hold_until,omitempty"` // manual hold: the lease cannot close before this
	// Gen is a daemon-wide counter that increases on every lease open or close
	// (persisted across restarts). Sessions apply an open only if Gen is newer
	// than what they hold for that (agent, space), and a close only if Gen is
	// newer or equal; stale pushes are ignored.
	Gen uint64 `json:"gen"`
}

// LeaseUpdate is pushed to every session of the lease's agent.
type LeaseUpdate struct {
	Lease  LeaseInfo `json:"lease"`
	Open   bool      `json:"open"`
	Reason string    `json:"reason,omitempty"` // when closing: "idle" | "expired" | "manual" | "hold-ended"
}

// ProcInfo describes one process in the chain that triggered an access.
type ProcInfo struct {
	PID     int    `json:"pid"`
	Comm    string `json:"comm"`
	Cmdline string `json:"cmdline"` // space-joined argv, truncated to ~200 chars
}

// AccessRequest asks the daemon to decide a gated access for which the
// session holds no open lease. The daemon answers with a Decision, possibly
// after prompting the user.
type AccessRequest struct {
	SessionID string     `json:"session_id"`
	AgentID   string     `json:"agent_id"`
	Space     string     `json:"space"`
	Op        string     `json:"op"`
	Target    string     `json:"target"`     // human display: "~/.ssh/id_ed25519", "10.0.0.5:22", "@/tmp/.X11-unix/X0"
	TargetKey string     `json:"target_key"` // canonical identity for allow-once, cooldown, and known-target tracking
	Label     string     `json:"label"`      // rule label: "SSH private key", "Shell startup file"
	RuleID    string     `json:"rule_id"`
	Detail    string     `json:"detail,omitempty"` // extra human context: "SSH (port 22)", "creates a new file", reverse DNS
	Syscall   string     `json:"syscall"`          // raw form for the details pane: `openat(AT_FDCWD, "/home/u/.ssh/id_ed25519", O_RDONLY)`
	PID       int        `json:"pid"`
	Chain     []ProcInfo `json:"chain"` // agent root first, requesting process last
	Cwd       string     `json:"cwd"`
	FromSpace string     `json:"from_space"`         // the Space the agent is currently working in
	Friction  string     `json:"friction,omitempty"` // rule-level friction override ("low"|"medium"|"high"), else the Space policy applies
}

// Decision scopes.
const (
	ScopeLease     = "lease"     // allowed; a lease is now open (Decision.Lease)
	ScopeOnce      = "once"      // allowed for this single operation (and identical waiters)
	ScopeDeny      = "deny"      // user denied
	ScopeTimeout   = "timeout"   // nobody answered before the prompt timeout
	ScopeCooldown  = "cooldown"  // auto-denied: the user denied the same target moments ago
	ScopeCancelled = "cancelled" // the request was cancelled (process died / daemon shutting down)
	ScopeError     = "error"     // internal failure; treat as deny
)

// Decision answers an AccessRequest.
type Decision struct {
	Allow  bool       `json:"allow"`
	Scope  string     `json:"scope"`
	Reason string     `json:"reason,omitempty"`
	Lease  *LeaseInfo `json:"lease,omitempty"` // set when Scope == ScopeLease
}

// Cancel withdraws a pending AccessRequest (identified by the envelope ID of
// the original access request on the same connection).
type Cancel struct {
	RequestID uint64 `json:"request_id"`
	Reason    string `json:"reason,omitempty"`
}

// Touch reports lease usage. Used maps space name -> last use. If a touch
// names a space whose lease is closed (or an older Gen), the daemon answers
// with a lease{open:false} push so the session drops its stale cache entry.
type Touch struct {
	AgentID string             `json:"agent_id"`
	Used    map[string]TouchAt `json:"used"`
	Current string             `json:"current,omitempty"` // the session's current working Space
}

// TouchAt is one space's usage in a Touch.
type TouchAt struct {
	At  time.Time `json:"at"`
	Gen uint64    `json:"gen"` // Gen of the lease the session believes is open
}

// Session event kinds.
const (
	EventEntered  = "entered"  // first use of a newly opened lease, or a new distinct target inside an open Remote/Vault/System/Device lease
	EventBlocked  = "blocked"  // hard-denied without prompting (Reclaim self-protection)
	EventObserved = "observed" // observe mode: a gated access with no open lease that WOULD have prompted (allowed)
)

// SessionEvent is an audit-worthy event observed by a session.
type SessionEvent struct {
	Kind    string `json:"kind"`
	Space   string `json:"space"`
	Op      string `json:"op"`
	Target  string `json:"target"`
	Label   string `json:"label,omitempty"`
	Detail  string `json:"detail,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
}

// PromptInfo is a pending pause-and-ask prompt as shown to the user.
type PromptInfo struct {
	ID          string     `json:"id"` // short, human-typeable (e.g. "k3f9")
	SessionID   string     `json:"session_id"`
	AgentID     string     `json:"agent_id"`
	Agent       string     `json:"agent"`
	Space       string     `json:"space"`
	Op          string     `json:"op"`
	Target      string     `json:"target"`
	TargetKey   string     `json:"target_key"`
	Label       string     `json:"label"`
	Detail      string     `json:"detail,omitempty"`
	Syscall     string     `json:"syscall"`
	Chain       []ProcInfo `json:"chain"`
	Cwd         string     `json:"cwd"`
	FromSpace   string     `json:"from_space"`           // where the agent currently is
	Why         string     `json:"why"`                  // reclamation context: "First time claude enters Vault Space." / "Reclaimed 3h ago after 15m of inactivity."
	Friction    string     `json:"friction"`             // "low" | "medium" | "high"
	Unexpected  bool       `json:"unexpected,omitempty"` // Remote target never approved before for this agent
	Challenge   string     `json:"challenge,omitempty"`  // high friction: the word the user must type
	ArmDelay    Duration   `json:"arm_delay"`            // input ignored until CreatedAt+ArmDelay
	AllowOnce   bool       `json:"allow_once"`           // "once" action offered
	LeaseText   string     `json:"lease_text"`           // what "allow" grants: "for 2m (fixed)" / "until 15m of inactivity"
	CreatedAt   time.Time  `json:"created_at"`
	Deadline    time.Time  `json:"deadline"`
	Waiting     int        `json:"waiting"`                // paused operations attached to this prompt
	MoreTargets []Waiter   `json:"more_targets,omitempty"` // other distinct targets waiting on the same Space
}

// Waiter is another paused operation attached to a prompt.
type Waiter struct {
	Target    string `json:"target"`
	TargetKey string `json:"target_key"`
	Op        string `json:"op"`
	Label     string `json:"label,omitempty"`
	SessionID string `json:"session_id"`
	Command   string `json:"command,omitempty"`
}

// Answer actions.
const (
	ActionAllow = "allow" // open a lease per the Space policy
	ActionOnce  = "once"  // allow only this operation (and waiters on the same target)
	ActionDeny  = "deny"
)

// Answer resolves a prompt. High-friction prompts require Challenge to match
// PromptInfo.Challenge (case-insensitive, trimmed) for allow/once; answers
// arriving before CreatedAt+ArmDelay are rejected with a TypeError whose
// message starts with "too fast".
//
// ActionOnce resolves only the waiters whose TargetKey equals the prompt's;
// the remaining waiters get a fresh prompt (new ID, same deadline).
// ActionDeny denies every waiter and records a cooldown per TargetKey.
type Answer struct {
	PromptID  string `json:"prompt_id"`
	Action    string `json:"action"`
	Challenge string `json:"challenge,omitempty"`
	Via       string `json:"via"` // "console" | "cli" | "dialog"
}

// ReclaimRequest revokes open leases immediately. Empty fields mean "all".
// Agent matches every AgentID of that agent name; AgentID matches exactly.
type ReclaimRequest struct {
	Agent   string `json:"agent,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Space   string `json:"space,omitempty"`
}

// ReclaimResult reports how many leases were revoked.
type ReclaimResult struct {
	Revoked int `json:"revoked"`
}

// HoldRequest manually holds a Space open until now+Duration: an open lease
// gets HoldUntil (normal decay resumes afterwards); a closed Space is opened
// with the policy lease plus the hold. Agent/AgentID match as in
// ReclaimRequest; both empty means every agent with a live session. The
// daemon answers TypeError when nothing matches.
type HoldRequest struct {
	Agent    string   `json:"agent,omitempty"`
	AgentID  string   `json:"agent_id,omitempty"`
	Space    string   `json:"space"`
	Duration Duration `json:"duration"`
}

// SetTTLRequest tunes a Space's lease duration (idle window for sliding,
// lifetime for fixed). Persisted by the daemon across restarts and applied
// over config.toml until Reset is sent (TTL ignored), which returns to the
// config value.
type SetTTLRequest struct {
	Space string   `json:"space"`
	TTL   Duration `json:"ttl"`
	Reset bool     `json:"reset,omitempty"`
}

// AuditQuery asks for recent audit events, newest last. Agent matches the
// agent name, AgentID the exact lease identity.
type AuditQuery struct {
	Limit   int    `json:"limit,omitempty"` // default 50
	Agent   string `json:"agent,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Space   string `json:"space,omitempty"`
}

// AuditResult answers AuditQuery.
type AuditResult struct {
	Events []AuditEvent `json:"events"`
}

// Audit event kinds.
const (
	AuditDaemonStart  = "daemon_start"
	AuditDaemonStop   = "daemon_stop"
	AuditSessionStart = "session_start"
	AuditSessionEnd   = "session_end"
	AuditGranted      = "granted"       // lease opened without a prompt (launch)
	AuditApproved     = "approved"      // user approved a prompt; lease opened
	AuditApprovedOnce = "approved_once" // user approved a single operation
	AuditDenied       = "denied"        // user denied
	AuditTimeout      = "timeout"       // prompt expired unanswered; operation failed with EACCES
	AuditAutoDenied   = "auto_denied"   // denied without prompting (cooldown after a recent denial)
	AuditCancelled    = "cancelled"     // prompt withdrawn (process exited)
	AuditEntered      = "entered"       // agent entered/used a Space under an open lease
	AuditReclaimed    = "reclaimed"     // lease closed automatically (idle / fixed expiry)
	AuditRevoked      = "revoked"       // lease closed manually ("reclaim now")
	AuditHeld         = "held"          // manual hold
	AuditTTLChanged   = "ttl_changed"
	AuditBlocked      = "blocked"    // hard-denied (Reclaim self-protection)
	AuditObserved     = "observed"   // observe mode: would have prompted (allowed without asking)
	AuditUnreadable   = "unreadable" // denied: the requesting process's arguments could not be read
)

// AuditEvent is one line of the audit log (JSONL on disk).
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	AgentID   string    `json:"agent_id,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Space     string    `json:"space,omitempty"`
	Op        string    `json:"op,omitempty"`
	Target    string    `json:"target,omitempty"`
	Label     string    `json:"label,omitempty"`
	Detail    string    `json:"detail,omitempty"`  // human context: "after 15m of inactivity", "fixed 2m", reason text
	By        string    `json:"by,omitempty"`      // "user:console" | "user:cli" | "user:dialog" | "timer" | "launch" | "session"
	Command   string    `json:"command,omitempty"` // requesting process command line
}

// State is a full snapshot of the daemon, used by status and the console.
type State struct {
	Now       time.Time             `json:"now"`
	DaemonPID int                   `json:"daemon_pid"`
	StartedAt time.Time             `json:"started_at"`
	Sessions  []SessionInfo         `json:"sessions"`
	Leases    []LeaseInfo           `json:"leases"`
	Prompts   []PromptInfo          `json:"prompts"`
	Policies  map[string]PolicyInfo `json:"policies"`
	Recent    []AuditEvent          `json:"recent"` // last ~20 audit events, newest last
	UIClients int                   `json:"ui_clients"`
}
