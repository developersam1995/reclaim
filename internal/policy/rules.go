package policy

import (
	"fmt"

	"reclaim/internal/config"
	"reclaim/internal/space"
)

// Rule maps filesystem paths and/or socket addresses to a Space.
//
// Pattern syntax (Paths, Except, Sockets): see package doc / ARCHITECTURE.md §3.
// "~" expands to the home directory, "$XDG_RUNTIME_DIR" to the user runtime
// dir (patterns using it are skipped when it is unknown), "{project}" to each
// project root. "**" as a whole segment spans zero or more segments, a leading
// "**/" matches at any depth, and "dir/**" also matches "dir" itself.
type Rule struct {
	ID       string         // stable identifier, e.g. "vault.ssh-keys"
	Space    space.Space    // target classification (may be space.Ambient)
	Label    string         // human description shown in prompts, e.g. "SSH private key"
	Paths    []string       // filesystem path globs (open/exec/rename/... targets)
	Except   []string       // path or socket globs that exclude a match from this rule
	Sockets  []string       // AF_UNIX socket path globs (connect/bind/sendto targets)
	Abstract []string       // abstract AF_UNIX socket name globs, without the leading '@'
	Agents   []string       // if non-empty, the rule only applies to these agent names
	Friction space.Friction // optional override of the Space's base friction (FrictionNone = use policy)
}

// AgentStateDefaults are the built-in self-state locations of common agents.
// They are Ambient for that agent only: an agent may always use its own state.
var AgentStateDefaults = map[string][]string{
	"claude": {"~/.claude/**", "~/.claude.json", "~/.claude.json.*", "~/.config/claude/**",
		"~/.local/share/claude/**", "~/.local/state/claude/**", "~/.cache/claude/**",
		"~/.cache/claude-cli-nodejs/**", "~/.local/bin/claude",
		"~/.vscode/extensions/anthropic.claude-code-*/**", "~/.vscode-server/extensions/anthropic.claude-code-*/**"},
	"codex":        {"~/.codex/**"},
	"gemini":       {"~/.gemini/**"},
	"aider":        {"~/.aider/**", "~/.aider.conf.yml", "~/.aider.model.settings.yml"},
	"opencode":     {"~/.local/share/opencode/**", "~/.config/opencode/**", "~/.cache/opencode/**", "~/.local/state/opencode/**"},
	"goose":        {"~/.config/goose/**", "~/.local/share/goose/**", "~/.local/state/goose/**"},
	"cursor-agent": {"~/.cursor/**", "~/.config/cursor/**"},
	"copilot":      {"~/.copilot/**", "~/.config/github-copilot/**"},
	"amp":          {"~/.config/amp/**", "~/.local/share/amp/**", "~/.cache/amp/**"},
}

// DefaultRules returns the built-in rules in evaluation order (layers 3–8 of
// ARCHITECTURE.md §3). Control (layer 0), user rules (1) and agent self-state
// (2) are prepended by the classifier; Ambient (9) is the fallback.
func DefaultRules() []Rule {
	return []Rule{
		// ── Device Space ─────────────────────────────────────────────────
		{ID: "device.camera", Space: space.Device, Label: "Camera",
			Paths: []string{"/dev/video*", "/dev/media*", "/dev/v4l/**"}},
		{ID: "device.audio", Space: space.Device, Label: "Microphone / audio device",
			Paths: []string{"/dev/snd/**"}},
		{ID: "device.input", Space: space.Device, Label: "Keyboard & mouse input (can log keystrokes)",
			Paths: []string{"/dev/input/**", "/dev/uinput", "/dev/hidraw*"}},
		{ID: "device.screen", Space: space.Device, Label: "Screen contents",
			Paths: []string{"/dev/fb*", "/dev/vcs*"}},
		{ID: "device.display", Space: space.Device, Label: "Display server (screen, keyboard, clipboard)",
			Sockets:  []string{"/tmp/.X11-unix/*", "$XDG_RUNTIME_DIR/wayland-*"},
			Abstract: []string{"/tmp/.X11-unix/X*"}},
		{ID: "device.media-server", Space: space.Device, Label: "Audio & screen-capture server (microphone, screen sharing)",
			Sockets: []string{"$XDG_RUNTIME_DIR/pipewire-*", "$XDG_RUNTIME_DIR/pulse/native"}},
		{ID: "device.display-cookie", Space: space.Device, Label: "Display access cookie (Xauthority)",
			Paths: []string{"~/.Xauthority", "$XDG_RUNTIME_DIR/.mutter-Xwaylandauth.*", "$XDG_RUNTIME_DIR/gdm/Xauthority"}},

		// ── Vault Space ──────────────────────────────────────────────────
		{ID: "vault.ssh-agent", Space: space.Vault, Label: "SSH agent (signs in with your SSH keys)",
			Sockets: []string{"$XDG_RUNTIME_DIR/keyring/ssh", "$XDG_RUNTIME_DIR/gcr/ssh",
				"$XDG_RUNTIME_DIR/ssh-agent.socket", "$XDG_RUNTIME_DIR/openssh_agent", "/tmp/ssh-*/agent.*"}},
		{ID: "vault.gpg-agent", Space: space.Vault, Label: "GPG agent (uses your GPG keys)",
			Sockets: []string{"$XDG_RUNTIME_DIR/gnupg/S.gpg-agent*", "~/.gnupg/S.gpg-agent*"}},
		{ID: "vault.ssh-keys", Space: space.Vault, Label: "SSH private key",
			Paths: []string{"~/.ssh/**"},
			Except: []string{"~/.ssh/config", "~/.ssh/config.d/**", "~/.ssh/known_hosts*", "**/*.pub",
				"~/.ssh/authorized_keys", "~/.ssh/rc", "~/.ssh/environment"}},
		{ID: "vault.gpg-keys", Space: space.Vault, Label: "GPG keys",
			Paths: []string{"~/.gnupg/**"}},
		{ID: "vault.keyring", Space: space.Vault, Label: "Password store / system keyring",
			Paths: []string{"~/.local/share/keyrings/**", "~/.password-store/**", "~/.config/op/**",
				"~/.local/share/kwalletd/**", "~/.config/Bitwarden/**", "~/.config/KeePassXC/**"}},
		{ID: "vault.aws", Space: space.Vault, Label: "AWS credentials",
			Paths: []string{"~/.aws/credentials", "~/.aws/sso/cache/**", "~/.aws/cli/cache/**"}},
		{ID: "vault.gcloud", Space: space.Vault, Label: "Google Cloud credentials",
			Paths: []string{"~/.config/gcloud/credentials.db", "~/.config/gcloud/access_tokens.db",
				"~/.config/gcloud/legacy_credentials/**", "~/.config/gcloud/application_default_credentials.json"}},
		{ID: "vault.cloud-other", Space: space.Vault, Label: "Cloud credentials",
			Paths: []string{"~/.azure/**", "~/.oci/**", "~/.config/doctl/**", "~/.terraform.d/credentials.tfrc.json",
				"~/.vault-token", "~/.config/rclone/rclone.conf", "~/.s3cfg", "~/.boto", "~/.databrickscfg"}},
		{ID: "vault.kube", Space: space.Vault, Label: "Kubernetes credentials (kubeconfig)",
			Paths: []string{"~/.kube/config", "~/.kube/config.d/**"}},
		{ID: "vault.docker", Space: space.Vault, Label: "Container registry credentials",
			Paths: []string{"~/.docker/config.json"}},
		{ID: "vault.db", Space: space.Vault, Label: "Database passwords",
			Paths: []string{"~/.pgpass", "~/.my.cnf", "~/.mylogin.cnf", "~/.snowsql/config",
				"~/.dbt/profiles.yml", "~/.config/dbt/profiles.yml"}},
		{ID: "vault.git", Space: space.Vault, Label: "Git / GitHub credentials",
			Paths: []string{"~/.git-credentials", "~/.config/git/credentials", "~/.config/gh/hosts.yml", "~/.config/hub"}},
		{ID: "vault.netrc", Space: space.Vault, Label: "Saved network passwords (.netrc)",
			Paths: []string{"~/.netrc"}},
		{ID: "vault.registry-tokens", Space: space.Vault, Label: "Package registry & API tokens",
			Paths: []string{"~/.pypirc", "~/.gem/credentials", "~/.cargo/credentials", "~/.cargo/credentials.toml",
				"~/.cache/huggingface/token", "~/.huggingface/token", "~/.config/ngrok/**", "~/.ngrok2/**"}},
		{ID: "vault.browser", Space: space.Vault, Label: "Browser profile (history, cookies, saved passwords)",
			Paths: []string{"~/.mozilla/**", "~/snap/firefox/common/.mozilla/**", "~/.config/google-chrome/**",
				"~/.config/chromium/**", "~/snap/chromium/common/chromium/**", "~/.config/BraveSoftware/**",
				"~/.config/microsoft-edge/**", "~/.config/vivaldi/**", "~/.config/opera/**",
				"~/.var/app/org.mozilla.firefox/**", "~/.var/app/com.google.Chrome/**",
				"~/.var/app/com.brave.Browser/**", "~/.var/app/org.chromium.Chromium/**"}},
		{ID: "vault.messaging", Space: space.Vault, Label: "Email & messaging app data",
			Paths: []string{"~/.thunderbird/**", "~/snap/thunderbird/**", "~/.config/Signal/**",
				"~/.config/Slack/**", "~/.config/discord/**", "~/.local/share/TelegramDesktop/**"}},
		{ID: "project.dotenv", Space: space.Project, Label: "Project .env file",
			Paths: []string{"{project}/**/.env", "{project}/**/.env.*"}},
		{ID: "vault.dotenv", Space: space.Vault, Label: ".env secrets file (outside the project)",
			Paths: []string{"**/.env", "**/.env.*"},
			Except: []string{"**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist",
				"**/.env.defaults", "**/.env.schema"}},
		{ID: "vault.shell-history", Space: space.Vault, Label: "Shell history (often contains pasted secrets)",
			Paths: []string{"~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history", "~/.history"}},
		{ID: "vault.db-clients", Space: space.Vault, Label: "Database client saved connections",
			Paths: []string{"~/.tableplus/**", "~/.local/share/DBeaverData/**", "~/.config/DBeaverData/**",
				"~/.config/pgadmin/**", "~/.dbeaver/**", "~/.streamlit/secrets.toml"}},
		{ID: "vault.misc-keys", Space: space.Vault, Label: "Other private keys & VPN credentials",
			Paths: []string{"~/.pki/nssdb/**", "~/.config/AWSVPNClient/**", "~/.android/adbkey", "~/.docker/contexts/**",
				"~/.config/Yubico/**", "~/.local/share/keyrings/**"}},
		{ID: "vault.process-env", Space: space.Vault, Label: "Another program's environment variables (often holds secrets)",
			Paths: []string{"/proc/[0-9]*/environ"}},

		// ── Remote Space ─────────────────────────────────────────────────
		{ID: "remote.ssh-config", Space: space.Remote, Label: "SSH client configuration",
			Paths: []string{"~/.ssh/config", "~/.ssh/config.d/**", "~/.ssh/known_hosts*", "~/.ssh/*.pub"}},
		{ID: "remote.ssh-connection", Space: space.Remote, Label: "Existing SSH connection (ControlMaster)",
			Sockets: []string{"~/.ssh/**", "/tmp/ssh-*@*"}},
		{ID: "remote.cloud-config", Space: space.Remote, Label: "Cloud CLI configuration",
			Paths: []string{"~/.aws/config", "~/.config/gcloud/configurations/**", "~/.kube/cache/**", "~/.kube/http-cache/**"}},

		// ── System Space (modification gate; reads are free) ─────────────
		{ID: "system.login-access", Space: space.System, Label: "SSH login access (who can log in to this machine)",
			Paths: []string{"~/.ssh/authorized_keys", "~/.ssh/rc", "~/.ssh/environment"}},
		{ID: "system.shell-startup", Space: space.System, Label: "Shell & session startup file",
			Paths: []string{"~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.bash_logout", "~/.bash_aliases",
				"~/.profile", "~/.zshrc", "~/.zshenv", "~/.zprofile", "~/.zlogin", "~/.zlogout",
				"~/.config/fish/**", "~/.inputrc", "~/.xprofile", "~/.xinitrc", "~/.xsession", "~/.xsessionrc",
				"~/.pam_environment", "~/.config/environment.d/**", "~/.tmux.conf", "~/.config/tmux/**", "~/.screenrc",
				"~/.dircolors", "~/.bash_completion", "~/.bash_completion.d/**", "~/.local/share/bash-completion/**",
				"~/.config/starship.toml", "~/.fzf.bash", "~/.fzf.zsh", "~/.oh-my-zsh/**", "~/.hushlogin"}},
		{ID: "system.autostart", Space: space.System, Label: "Autostart entries & background services",
			Paths: []string{"~/.config/autostart/**", "~/.config/systemd/**", "~/.local/share/systemd/**",
				"~/.config/upstart/**", "~/.kde/Autostart/**", "~/.config/plasma-workspace/env/**",
				"~/.local/share/applications/**", "~/.config/mimeapps.list", "~/.local/share/dbus-1/services/**"}},
		{ID: "system.user-packages", Space: space.System, Label: "User-level package install (lands on your PATH)", Friction: space.FrictionMedium,
			Paths: []string{"~/.local/lib/python*/site-packages/**", "~/go/bin/**", "~/.cargo/bin/**", "~/.local/share/gem/**",
				"~/.local/pipx/**", "~/.local/share/pipx/**", "~/.local/share/pypoetry/**", "~/.npm-global/**",
				"~/.local/share/pnpm/**", "~/.bun/bin/**", "~/.deno/bin/**"},
			Except: []string{"~/.local/share/pnpm/store/**"}},
		{ID: "system.user-software", Space: space.System, Label: "Globally installed software (on your PATH)",
			Paths: []string{"~/.local/bin/**", "~/bin/**", "~/.nix-profile/**", "/nix/**"}},
		{ID: "system.env-files", Space: space.System, Label: "File sourced by every new shell",
			Paths: []string{"~/.cargo/env", "~/.cargo/env.*", "~/.ghcup/env", "~/.deno/env", "~/.fzf/**",
				"~/.config/go/env", "~/.ipython/profile_*/startup/**", "~/.ipython/profile_*/ipython_config.py",
				"~/.jupyter/*.py", "~/.docker/cli-plugins/**"}},
		{ID: "system.editor-runtime", Space: space.System, Label: "Editor extensions & servers (run outside the agent session)",
			Paths: []string{"~/.vscode/extensions/**", "~/.vscode-server/**", "~/.cursor-server/**"}},
		{ID: "system.tool-config", Space: space.System, Label: "Developer tool configuration (can run code on your behalf)",
			Paths: []string{"~/.gitconfig", "~/.config/git/**", "~/.npmrc", "~/.yarnrc", "~/.yarnrc.yml",
				"~/.config/pip/**", "~/.pip/**", "~/.cargo/config", "~/.cargo/config.toml", "~/.vimrc", "~/.vim/**",
				"~/.config/nvim/**", "~/.emacs", "~/.emacs.d/**", "~/.config/Code/User/**", "~/.config/Cursor/User/**"}},
		{ID: "project.files", Space: space.Project, Label: "Project files",
			Paths: []string{"{project}/**"}},
		{ID: "system.dirs", Space: space.System, Label: "System configuration & software",
			Paths:  []string{"/etc/**", "/usr/**", "/opt/**", "/var/**", "/boot/**", "/bin/**", "/sbin/**", "/lib/**", "/lib32/**", "/lib64/**", "/libx32/**", "/snap/**", "/srv/**"},
			Except: []string{"/var/tmp/**"}},
		{ID: "system.session-bus", Space: space.System, Label: "Desktop session bus (keyring, background services, screen-sharing portals)",
			Sockets:  []string{"$XDG_RUNTIME_DIR/bus", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"},
			Abstract: []string{"/tmp/dbus-*"}},
		{ID: "system.systemd", Space: space.System, Label: "systemd (start or enable background services)",
			Sockets: []string{"$XDG_RUNTIME_DIR/systemd/**", "/run/systemd/private", "/run/systemd/io.systemd.*"}},
		{ID: "system.containers", Space: space.System, Label: "Container engine (can mount any folder; root-equivalent)",
			Sockets: []string{"/var/run/docker.sock", "/run/docker.sock", "$XDG_RUNTIME_DIR/docker.sock",
				"$XDG_RUNTIME_DIR/podman/podman.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"}},
		{ID: "system.terminal-mux", Space: space.System, Label: "Terminal multiplexer (runs commands outside the agent session)",
			Sockets: []string{"/tmp/tmux-*/**", "/run/screen/**", "/tmp/screens/**"}},
		{ID: "system.editor-ipc", Space: space.System, Label: "Editor control socket (opens terminals outside the agent session)",
			Sockets: []string{"$XDG_RUNTIME_DIR/vscode-*.sock", "$XDG_RUNTIME_DIR/vscode-ipc-*.sock"}},

		// ── Project Space ────────────────────────────────────────────────
		{ID: "project.toolchains", Space: space.Project, Label: "Developer toolchains & caches",
			Paths: []string{"~/.cache/**", "~/go/pkg/**", "~/go/src/**", "~/sdk/**", "~/.cargo/registry/**", "~/.cargo/git/**",
				"~/.rustup/**", "~/.npm/**", "~/.pnpm-store/**", "~/.local/share/pnpm/store/**", "~/.yarn/**",
				"~/.m2/**", "~/.gradle/**", "~/.sbt/**", "~/.ivy2/**", "~/.nvm/**", "~/.pyenv/**", "~/.rbenv/**",
				"~/.local/share/uv/**", "~/.local/share/virtualenvs/**", "~/.local/share/mise/**", "~/.asdf/**",
				"~/.volta/**", "~/.bun/**", "~/.deno/**", "~/.sdkman/**", "~/.conda/**", "~/miniconda3/**",
				"~/anaconda3/**", "~/.dotnet/**", "~/.nuget/**", "~/.julia/**", "~/.ghcup/**", "~/.stack/**",
				"~/.elan/**", "~/.opam/**", "~/.local/share/containers/**", "~/.config/go/**", "~/.local/share/go/**",
				"~/.config/configstore/**",
				"~/.node-gyp/**", "~/.terraform.d/plugin-cache/**", "~/.ipython/**", "~/.jupyter/**",
				"~/.local/share/jupyter/**", "~/.config/matplotlib/**", "~/.docker/**", "~/.dbt/.user.yml",
				"~/.vscode/**", "~/.config/Code/**", "~/.config/Cursor/**"}},
		{ID: "project.tool-state", Space: space.Project, Label: "Developer tool history & state files",
			Paths: []string{"~/.lesshst", "~/.wget-hsts", "~/.psql_history", "~/.mysql_history", "~/.sqlite_history",
				"~/.python_history", "~/.node_repl_history", "~/.rediscli_history", "~/.duckdb_history",
				"~/.selected_editor", "~/.viminfo", "~/.local/state/vim/**", "~/.local/state/nvim/**"}},

		// ── Home Space ───────────────────────────────────────────────────
		{ID: "home.files", Space: space.Home, Label: "Personal files",
			Paths: []string{"~/**"}},
		{ID: "project.tmp", Space: space.Project, Label: "Temporary build files",
			Paths: []string{"/tmp/**", "/var/tmp/**", "/dev/shm/**"}},
		{ID: "home.external", Space: space.Home, Label: "External drives",
			Paths: []string{"/media/**", "/mnt/**", "/run/media/**"}},
	}
}

// RulesFromConfig converts user rules and agent state config into Rules.
// User rules get IDs "user.<id>" (or "user.<index>"); agent state rules get
// "agent.<name>" and Space Ambient, scoped to that agent.
func RulesFromConfig(cfg config.Config) (user []Rule, agentState []Rule, err error) {
	for i, rc := range cfg.Rules {
		sp, err := space.Parse(rc.Space)
		if err != nil {
			return nil, nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		id := rc.ID
		if id == "" {
			id = fmt.Sprint(i)
		}
		label := rc.Label
		if label == "" {
			label = sp.Title()
		}
		var fr space.Friction
		if rc.Friction != "" {
			if fr, err = space.ParseFriction(rc.Friction); err != nil {
				return nil, nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
		}
		user = append(user, Rule{ID: "user." + id, Space: sp, Label: label, Friction: fr,
			Paths: rc.Paths, Except: rc.Except, Sockets: rc.Sockets, Abstract: rc.Abstract, Agents: rc.Agents})
	}
	seen := map[string]bool{}
	add := func(name string, globs []string) {
		if len(globs) == 0 {
			return
		}
		agentState = append(agentState, Rule{ID: "agent." + name, Space: space.Ambient,
			Label: name + "'s own state", Paths: globs, Agents: []string{name}})
	}
	for name, ac := range cfg.Agents {
		seen[name] = true
		add(name, append(append([]string(nil), AgentStateDefaults[name]...), ac.State...))
	}
	for name, globs := range AgentStateDefaults {
		if !seen[name] {
			add(name, globs)
		}
	}
	return user, agentState, nil
}
