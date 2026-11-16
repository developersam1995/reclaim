package policy

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"reclaim/internal/space"
)

func testEnv(agent string) Env {
	return Env{Home: "/home/u", RuntimeDir: "/run/user/1000", Projects: []string{"/home/u/projects/demo"}, Agent: agent,
		ControlPaths:  []string{"/home/u/.config/reclaim", "/home/u/.local/state/reclaim", "/run/user/1000/reclaim"},
		ControlSocket: "/run/user/1000/reclaim/reclaimd.sock"}
}

func newTest(t *testing.T, agent string, user []Rule) *Classifier {
	t.Helper()
	_, agentState, _ := RulesFromConfigLike(nil)
	c, err := New(testEnv(agent), user, agentState, Network{ControlPlanePorts: []int{443}, DNSIsLocal: true,
		LocalCIDRs: []*net.IPNet{mustCIDR("192.168.0.0/16")}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// RulesFromConfigLike builds the default agent-state rules without a config.
func RulesFromConfigLike(_ any) ([]Rule, []Rule, error) {
	var agentState []Rule
	for name, globs := range AgentStateDefaults {
		agentState = append(agentState, Rule{ID: "agent." + name, Space: space.Ambient, Label: name + "'s own state", Paths: globs, Agents: []string{name}})
	}
	return nil, agentState, nil
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestClassifyPaths(t *testing.T) {
	c := newTest(t, "claude", nil)
	cases := []struct {
		path string
		want space.Space
	}{
		{"/home/u/.ssh/id_ed25519", space.Vault},
		{"/home/u/.ssh/id_ed25519.pub", space.Remote},
		{"/home/u/.ssh/config", space.Remote},
		{"/home/u/.ssh/authorized_keys", space.System},
		{"/home/u/.ssh", space.Vault},
		{"/home/u/.gitconfig", space.System},
		{"/home/u/projects/demo/main.go", space.Project},
		{"/home/u/projects/demo", space.Project},
		{"/home/u/projects/demo/.env", space.Project},
		{"/home/u/projects/demo/sub/.env.local", space.Project},
		{"/home/u/other/.env", space.Vault},
		{"/home/u/other/.env.example", space.Home},
		{"/tmp/x", space.Project},
		{"/home/u/.cache/go-build/ab/cd", space.Project},
		{"/home/u/.local/bin/claude", space.Ambient},
		{"/home/u/.claude/settings.json", space.Ambient},
		{"/home/u/.local/lib/python3.12/site-packages/foo.py", space.System},
		{"/home/u/Documents/a.pdf", space.Home},
		{"/home/u/.cargo/env", space.System},
		{"/home/u/.bash_history", space.Vault},
		{"/home/u/.tableplus/data", space.Vault},
		{"/etc/hosts", space.System},
		{"/usr/lib/x.so", space.System},
		{"/proc/1234/environ", space.Vault},
		{"/proc/cpuinfo", space.Ambient},
		{"/dev/null", space.Ambient},
		{"/dev/video0", space.Device},
		{"/home/u/.config/reclaim/config.toml", space.Control},
		{"/run/user/1000/reclaim", space.Control},
		{"/media/usb/x", space.Home},
		{"/home/u", space.Home},
		{"/", space.Ambient},
	}
	for _, cs := range cases {
		got := c.ClassifyPath(PathTarget{Lexical: cs.path, SelfPID: 99})
		if got.Space != cs.want {
			t.Errorf("%s: got %s (%s), want %s", cs.path, got.Space, got.RuleID, cs.want)
		}
	}
	if r := c.ClassifyPath(PathTarget{Lexical: "/home/u/.local/lib/python3.12/site-packages/foo.py"}); r.Friction != space.FrictionMedium {
		t.Errorf("site-packages friction = %v", r.Friction)
	}
	if r := c.ClassifyPath(PathTarget{Lexical: "/proc/1234/environ", SelfPID: 1234}); r.Space != space.Ambient || r.RuleID != "ambient.self" {
		t.Errorf("own environ = %+v", r)
	}
	r := c.ClassifyPath(PathTarget{Lexical: "/home/u/projects/demo/link", Resolved: "/home/u/.ssh/id_rsa"})
	if r.Space != space.Vault || r.Display != "~/projects/demo/link → ~/.ssh/id_rsa" || r.Key != "/home/u/.ssh/id_rsa" {
		t.Errorf("symlink = %+v", r)
	}
	// Other agents: claude's state is Home for codex, its binary System.
	c2 := newTest(t, "codex", nil)
	if r := c2.ClassifyPath(PathTarget{Lexical: "/home/u/.claude/settings.json"}); r.Space != space.Home {
		t.Errorf("codex reading claude state = %v", r.Space)
	}
	if r := c2.ClassifyPath(PathTarget{Lexical: "/home/u/.local/bin/claude"}); r.Space != space.System {
		t.Errorf("codex writing claude binary = %v", r.Space)
	}
}

func TestUserRulesAndErrors(t *testing.T) {
	user := []Rule{{ID: "user.lake", Space: space.Vault, Label: "Lake creds", Paths: []string{"~/Documents/lake/**"}, Except: []string{"~/Documents/lake/README*"}}}
	c := newTest(t, "claude", user)
	if r := c.ClassifyPath(PathTarget{Lexical: "/home/u/Documents/lake/token"}); r.Space != space.Vault || r.RuleID != "user.lake" {
		t.Errorf("user rule = %+v", r)
	}
	if r := c.ClassifyPath(PathTarget{Lexical: "/home/u/Documents/lake/README.md"}); r.Space != space.Home {
		t.Errorf("user except = %+v", r)
	}
	if _, err := New(testEnv("x"), []Rule{{ID: "bad", Space: space.Home, Paths: []string{"relative/x"}}}, nil, Network{}); err == nil {
		t.Error("relative pattern should fail")
	}
	if _, err := New(testEnv("x"), []Rule{{ID: "bad", Space: space.Home, Paths: []string{"/a/[x"}}}, nil, Network{}); err == nil {
		t.Error("malformed pattern should fail")
	}
	// No runtime dir: patterns using it are dropped, others still work.
	env := testEnv("claude")
	env.RuntimeDir = ""
	env.Projects = nil
	c2, err := New(env, nil, nil, Network{})
	if err != nil {
		t.Fatal(err)
	}
	if r := c2.ClassifySocket(space.OpConnect, SockTarget{Family: "unix", Path: "/run/user/1000/bus"}, false, nil); r.Space != space.Ambient {
		t.Errorf("dropped runtime pattern still matched: %+v", r)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/a/**", "/a", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**", "/ab", false},
		{"**/.env", "/.env", true},
		{"**/.env", "/x/y/.env", true},
		{"**/.env", "/x/.envy", false},
		{"/a/**/b", "/a/b", true},
		{"/a/**/b", "/a/x/y/b", true},
		{"/dev/video*", "/dev/video12", true},
		{"/proc/[0-9]*/environ", "/proc/42/environ", true},
		{"/proc/[0-9]*/environ", "/proc/self/environ", false},
		{"/home/u/.local/lib/python*/site-packages/**", "/home/u/.local/lib/python3.12/site-packages/x/y.py", true},
	}
	for _, c := range cases {
		g, err := compileGlob(c.pat)
		if err != nil {
			t.Fatal(err)
		}
		if got := g.match(c.p); got != c.want {
			t.Errorf("%s ~ %s = %v, want %v", c.pat, c.p, got, c.want)
		}
	}
	for _, r := range DefaultRules() {
		for _, pats := range [][]string{r.Paths, r.Except, r.Sockets} {
			for _, p := range pats {
				for _, e := range expand(p, testEnv("x")) {
					if _, err := compileGlob(e); err != nil {
						t.Errorf("rule %s: %v", r.ID, err)
					}
				}
			}
		}
	}
}

func TestSockets(t *testing.T) {
	c := newTest(t, "claude", nil)
	unixCases := []struct {
		path string
		want space.Space
	}{
		{"/run/user/1000/bus", space.System},
		{"/run/user/1000/gcr/ssh", space.Vault},
		{"/run/user/1000/wayland-0", space.Device},
		{"/tmp/.X11-unix/X0", space.Device},
		{"/var/run/docker.sock", space.System},
		{"/var/run/postgresql/.s.PGSQL.5432", space.Ambient},
		{"/run/user/1000/reclaim/reclaimd.sock", space.Control},
		{"/home/u/.ssh/cm-host-22", space.Remote},
	}
	for _, cs := range unixCases {
		if r := c.ClassifySocket(space.OpConnect, SockTarget{Family: "unix", Path: cs.path}, false, nil); r.Space != cs.want {
			t.Errorf("unix %s: got %s (%s), want %s", cs.path, r.Space, r.RuleID, cs.want)
		}
	}
	if r := c.ClassifySocket(space.OpConnect, SockTarget{Family: "abstract", Path: "/tmp/.X11-unix/X0"}, false, nil); r.Space != space.Device || r.Display != "@/tmp/.X11-unix/X0" {
		t.Errorf("abstract = %+v", r)
	}
	// Hard link to the control socket, detected by dev/ino.
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	env := testEnv("claude")
	env.ControlSocket = sock
	c3, _ := New(env, nil, nil, Network{})
	fi, _ := os.Stat(sock)
	st := fi.Sys().(*syscall.Stat_t)
	if r := c3.ClassifySocket(space.OpConnect, SockTarget{Family: "unix", Path: "/elsewhere/link", Dev: uint64(st.Dev), Ino: st.Ino}, false, nil); r.Space != space.Control {
		t.Errorf("hard link to control socket = %+v", r)
	}

	ip := func(s string) net.IP { return net.ParseIP(s) }
	cp := func(i net.IP) (string, bool) { return "api.anthropic.com", i.Equal(ip("1.2.3.4")) }
	inet := []struct {
		op       space.Op
		ip       string
		port     int
		fromRoot bool
		want     space.Space
		detail   string
	}{
		{space.OpConnect, "127.0.0.1", 5432, false, space.Ambient, ""},
		{space.OpConnect, "::1", 22, false, space.Ambient, ""},
		{space.OpConnect, "8.8.8.8", 53, false, space.Ambient, ""},
		{space.OpConnect, "10.1.2.3", 22, false, space.Remote, "SSH (port 22)"},
		{space.OpConnect, "1.2.3.4", 443, true, space.Ambient, ""},
		{space.OpConnect, "5.6.7.8", 443, true, space.Ambient, ""},
		{space.OpConnect, "5.6.7.8", 443, false, space.Remote, "HTTPS (port 443)"},
		{space.OpConnect, "1.2.3.4", 443, false, space.Ambient, ""},
		{space.OpConnect, "::ffff:10.0.0.1", 80, false, space.Remote, "HTTP (port 80)"},
		{space.OpConnect, "192.168.1.5", 22, false, space.Ambient, ""},
		{space.OpConnect, "169.254.169.254", 80, false, space.Remote, "Cloud instance metadata service (can hand out credentials)"},
		{space.OpListen, "0.0.0.0", 3000, false, space.Remote, ""},
		{space.OpListen, "127.0.0.1", 3000, false, space.Ambient, ""},
		{space.OpListen, "0.0.0.0", 0, false, space.Ambient, ""},
	}
	for _, cs := range inet {
		fam := "inet"
		if ip(cs.ip).To4() == nil {
			fam = "inet6"
		}
		r := c.ClassifySocket(cs.op, SockTarget{Family: fam, IP: ip(cs.ip), Port: cs.port}, cs.fromRoot, cp)
		if r.Space != cs.want || (cs.detail != "" && r.Detail != cs.detail) {
			t.Errorf("%s %s:%d root=%v: got %s %q (%s), want %s %q", cs.op, cs.ip, cs.port, cs.fromRoot, r.Space, r.Detail, r.RuleID, cs.want, cs.detail)
		}
	}
	if r := c.ClassifySocket(space.OpConnect, SockTarget{Family: "inet", IP: ip("::ffff:10.0.0.1"), Port: 80}, false, nil); r.Display != "10.0.0.1:80" {
		t.Errorf("v4-mapped display = %q", r.Display)
	}
	if r := c.ClassifySocket(space.OpListen, SockTarget{Family: "inet", IP: ip("0.0.0.0"), Port: 3000}, false, nil); r.Display != "*:3000" {
		t.Errorf("listen display = %q", r.Display)
	}
}

func BenchmarkClassifyPath(b *testing.B) {
	c, _ := New(testEnv("claude"), nil, nil, Network{})
	paths := []string{"/home/u/projects/demo/internal/x/y.go", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/home/u/.ssh/id_ed25519", "/tmp/go-build/x"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.ClassifyPath(PathTarget{Lexical: paths[i%len(paths)]})
	}
}
