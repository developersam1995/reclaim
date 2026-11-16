package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"reclaim/internal/config"
)

// ForSession builds the classifier for one agent session (also used by
// `reclaim explain`). exe is the reclaim executable path (Control).
func ForSession(paths config.Paths, cfg config.Config, agent string, projects []string, exe string) (*Classifier, error) {
	user, agentState, err := RulesFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	for _, c := range cfg.Network.LocalCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("network.local_cidrs: %w", err)
		}
		nets = append(nets, n)
	}
	control := []string{paths.ConfigDir, paths.StateDir, paths.RuntimeDir}
	if exe != "" {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		control = append(control, exe)
	}
	env := Env{
		Home:          paths.Home,
		RuntimeDir:    os.Getenv("XDG_RUNTIME_DIR"),
		Projects:      projects,
		Agent:         agent,
		ControlPaths:  control,
		ControlSocket: paths.Socket,
		SSHAuthSock:   os.Getenv("SSH_AUTH_SOCK"),
	}
	return New(env, user, agentState, Network{
		ControlPlanePorts: cfg.Network.ControlPlanePorts,
		LocalCIDRs:        nets,
		DNSIsLocal:        cfg.DNSLocal(),
	})
}
