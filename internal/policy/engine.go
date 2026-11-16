package policy

import (
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"reclaim/internal/space"
)

type compiledRule struct {
	Rule
	paths, except, sockets, abstract *globSet
}

type classifierImpl struct {
	env      Env
	net      Network
	compiled []compiledRule
	ctlIP    net.IP
}

func newClassifierImpl(env Env, userRules, agentState []Rule, netcfg Network) (*classifierImpl, error) {
	c := &classifierImpl{env: env, net: netcfg}
	var ordered []Rule
	ctl := Rule{ID: "control", Space: space.Control, Label: "Reclaim's own configuration and state"}
	for _, p := range env.ControlPaths {
		if p == "" {
			continue
		}
		ctl.Paths = append(ctl.Paths, p, p+"/**")
	}
	if env.ControlSocket != "" {
		ctl.Sockets = append(ctl.Sockets, env.ControlSocket)
	}
	if len(ctl.Paths) > 0 || len(ctl.Sockets) > 0 {
		ordered = append(ordered, ctl)
	}
	ordered = append(ordered, userRules...)
	ordered = append(ordered, agentState...)
	if env.SSHAuthSock != "" {
		ordered = append(ordered, Rule{ID: "vault.ssh-agent-env", Space: space.Vault,
			Label: "SSH agent (signs in with your SSH keys)", Sockets: []string{env.SSHAuthSock}})
	}
	ordered = append(ordered, DefaultRules()...)
	for _, r := range ordered {
		if len(r.Agents) > 0 {
			ok := false
			for _, a := range r.Agents {
				if a == env.Agent {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		cr, err := c.compile(r)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		c.compiled = append(c.compiled, cr)
	}
	return c, nil
}

func (c *classifierImpl) compile(r Rule) (compiledRule, error) {
	exp := func(pats []string) []string {
		var out []string
		for _, p := range pats {
			out = append(out, expand(p, c.env)...)
		}
		return out
	}
	cr := compiledRule{Rule: r}
	cr.Rule.Paths, cr.Rule.Except, cr.Rule.Sockets, cr.Rule.Abstract = exp(r.Paths), exp(r.Except), exp(r.Sockets), exp(r.Abstract)
	var err error
	if len(cr.Rule.Paths) > 0 {
		if cr.paths, err = newGlobSet(cr.Rule.Paths); err != nil {
			return cr, err
		}
	}
	if len(cr.Rule.Except) > 0 {
		if cr.except, err = newGlobSet(cr.Rule.Except); err != nil {
			return cr, err
		}
	}
	if len(cr.Rule.Sockets) > 0 {
		if cr.sockets, err = newGlobSet(cr.Rule.Sockets); err != nil {
			return cr, err
		}
	}
	if len(cr.Rule.Abstract) > 0 {
		abs := make([]string, len(cr.Rule.Abstract))
		for i, a := range cr.Rule.Abstract {
			abs[i] = "/" + strings.TrimPrefix(a, "/")
		}
		if cr.abstract, err = newGlobSet(abs); err != nil {
			return cr, err
		}
	}
	return cr, nil
}

func (c *classifierImpl) rules() []Rule {
	out := make([]Rule, len(c.compiled))
	for i, r := range c.compiled {
		out[i] = r.Rule
	}
	return out
}

func pretty(home, p string) string {
	if home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

func ambient(label string) Result {
	return Result{Space: space.Ambient, RuleID: "ambient", Label: label}
}

func (c *classifierImpl) matchPath(p string) Result {
	comps := splitPath(p)
	for i := range c.compiled {
		r := &c.compiled[i]
		if r.paths == nil || !r.paths.matchComps(comps) {
			continue
		}
		if r.except != nil && r.except.matchComps(comps) {
			continue
		}
		return Result{Space: r.Space, RuleID: r.ID, Label: r.Label, Friction: r.Friction}
	}
	return ambient("System runtime")
}

func (c *classifierImpl) classifyPath(t PathTarget) Result {
	lex := t.Lexical
	res := t.Resolved
	if res == "" {
		res = lex
	}
	if t.SelfPID > 0 {
		self := "/proc/" + strconv.Itoa(t.SelfPID)
		if lex == self || strings.HasPrefix(lex, self+"/") || res == self || strings.HasPrefix(res, self+"/") {
			return Result{Space: space.Ambient, RuleID: "ambient.self", Label: "The process's own /proc entry",
				Display: pretty(c.env.Home, lex), Key: res}
		}
	}
	rl := c.matchPath(lex)
	out := rl
	fromResolved := false
	if res != lex {
		rr := c.matchPath(res)
		if rr.Space.Rank() >= rl.Space.Rank() {
			out = rr
			fromResolved = true
		}
	}
	out.Key = res
	out.Display = pretty(c.env.Home, lex)
	if fromResolved && out.Space != rl.Space {
		out.Display += " → " + pretty(c.env.Home, res)
	}
	return out
}

var services = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 465: "SMTP",
	587: "SMTP", 873: "rsync", 993: "IMAPS", 1433: "SQL Server", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 5439: "Redshift", 5900: "VNC", 6379: "Redis", 8080: "HTTP (alt)",
	8443: "HTTPS (alt)", 9092: "Kafka", 9200: "Elasticsearch", 27017: "MongoDB",
}

func serviceDetail(ip net.IP, port int) string {
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return "Cloud instance metadata service (can hand out credentials)"
	}
	if s, ok := services[port]; ok {
		return fmt.Sprintf("%s (port %d)", s, port)
	}
	return ""
}

func (c *classifierImpl) classifySocket(op space.Op, t SockTarget, fromRoot bool, controlPlane func(net.IP) (string, bool)) Result {
	switch t.Family {
	case "unix":
		return c.classifyUnix(t)
	case "abstract":
		r := Result{Display: "@" + t.Path, Key: "abstract:" + t.Path}
		name := "/" + strings.TrimPrefix(t.Path, "/")
		for i := range c.compiled {
			cr := &c.compiled[i]
			if cr.abstract != nil && cr.abstract.match(name) {
				r.Space, r.RuleID, r.Label, r.Friction = cr.Space, cr.ID, cr.Label, cr.Friction
				return r
			}
		}
		r.Space, r.RuleID, r.Label = space.Ambient, "ambient", "Local socket"
		return r
	case "inet", "inet6":
		return c.classifyInet(op, t, fromRoot, controlPlane)
	}
	return ambient("Local socket")
}

func (c *classifierImpl) classifyUnix(t SockTarget) Result {
	if t.Path == "" {
		return ambient("Unnamed socket")
	}
	res := t.Resolved
	if res == "" {
		res = t.Path
	}
	r := Result{Display: pretty(c.env.Home, t.Path), Key: "unix:" + res}
	if c.env.ControlSocket != "" {
		if t.Path == c.env.ControlSocket || res == c.env.ControlSocket || c.isControlInode(t) {
			r.Space, r.RuleID, r.Label = space.Control, "control", "Reclaim's own control socket"
			return r
		}
	}
	best := ambient("Local socket")
	for _, p := range []string{t.Path, res} {
		for i := range c.compiled {
			cr := &c.compiled[i]
			if cr.sockets == nil || !cr.sockets.match(p) {
				continue
			}
			if cr.except != nil && cr.except.match(p) {
				continue
			}
			if cr.Space.Rank() > best.Space.Rank() || best.RuleID == "ambient" {
				best = Result{Space: cr.Space, RuleID: cr.ID, Label: cr.Label, Friction: cr.Friction}
			}
			break
		}
	}
	r.Space, r.RuleID, r.Label, r.Friction = best.Space, best.RuleID, best.Label, best.Friction
	return r
}

func (c *classifierImpl) isControlInode(t SockTarget) bool {
	if t.Ino == 0 {
		return false
	}
	fi, err := os.Stat(c.env.ControlSocket)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Ino == t.Ino && uint64(st.Dev) == t.Dev
}

func (c *classifierImpl) classifyInet(op space.Op, t SockTarget, fromRoot bool, controlPlane func(net.IP) (string, bool)) Result {
	ip := t.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	port := t.Port
	var disp string
	switch {
	case op == space.OpListen && ip.IsUnspecified():
		disp = "*:" + strconv.Itoa(port)
	case len(ip) == net.IPv6len:
		disp = "[" + ip.String() + "]:" + strconv.Itoa(port)
	default:
		disp = ip.String() + ":" + strconv.Itoa(port)
	}
	r := Result{Display: disp, Key: "net:" + ip.String() + ":" + strconv.Itoa(port), Detail: serviceDetail(ip, port)}
	set := func(sp space.Space, id, label string) Result {
		r.Space, r.RuleID, r.Label = sp, id, label
		return r
	}
	if op == space.OpListen {
		r.Key = "listen:" + strconv.Itoa(port)
		switch {
		case port == 0:
			return set(space.Ambient, "net.ephemeral", "Ephemeral local port")
		case ip.IsLoopback():
			return set(space.Ambient, "net.loopback", "Loopback")
		}
		return set(space.Remote, "net.listen", "Accept connections from the network")
	}
	switch {
	case ip.IsLoopback() || ip.IsUnspecified():
		return set(space.Ambient, "net.loopback", "Loopback")
	case port == 53 && c.net.DNSIsLocal:
		return set(space.Ambient, "net.dns", "DNS lookup")
	}
	for _, n := range c.net.LocalCIDRs {
		if n.Contains(ip) {
			return set(space.Ambient, "net.local", "Local network")
		}
	}
	if fromRoot {
		for _, p := range c.net.ControlPlanePorts {
			if p == port {
				return set(space.Ambient, "net.control-plane", "Agent control plane")
			}
		}
	}
	if controlPlane != nil && port == 443 {
		if host, ok := controlPlane(ip); ok {
			return set(space.Ambient, "net.control-plane", "Agent control plane ("+host+")")
		}
	}
	return set(space.Remote, "net.remote", "Network connection")
}

// Ensure path is referenced (used by Pretty callers for cleaning elsewhere).
var _ = path.Clean
