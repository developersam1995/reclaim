package policy

import (
	"fmt"
	"path"
	"strings"
)

// glob is a compiled path pattern. Segments are matched one at a time with
// path.Match semantics; "**" as a whole segment spans zero or more segments.
type glob struct {
	src      string
	segs     []string // without the leading "" of an absolute path
	anchored bool     // starts with "**/" → may match at any depth
	first    string   // first literal segment for indexing ("" if none)
	dirAlso  bool     // "dir/**" matches "dir" itself
}

func compileGlob(pat string) (*glob, error) {
	if pat == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	anchored := strings.HasPrefix(pat, "**/")
	if !anchored && !strings.HasPrefix(pat, "/") {
		return nil, fmt.Errorf("pattern %q must be absolute or start with **/", pat)
	}
	trailingAll := strings.HasSuffix(pat, "/**")
	cleaned := path.Clean(pat)
	if trailingAll && !strings.HasSuffix(cleaned, "/**") {
		cleaned += "/**"
	}
	segs := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	g := &glob{src: pat, segs: segs, anchored: anchored, dirAlso: trailingAll}
	for _, s := range segs {
		if s == "**" {
			continue
		}
		if _, err := path.Match(s, ""); err != nil {
			return nil, fmt.Errorf("pattern %q: %w", pat, err)
		}
	}
	for _, s := range segs {
		if s == "**" {
			break
		}
		if !strings.ContainsAny(s, "*?[\\") {
			g.first = s
		}
		break
	}
	return g, nil
}

// match reports whether p (absolute, cleaned) matches the glob.
func (g *glob) match(p string) bool { return g.matchComps(splitPath(p)) }

func (g *glob) matchComps(comps []string) bool { return matchSegs(g.segs, comps, g.dirAlso) }

// splitPath splits an absolute cleaned path into components ("/" → none).
func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	n := strings.Count(p, "/") + 1
	comps := make([]string, 0, n)
	for {
		i := strings.IndexByte(p, '/')
		if i < 0 {
			return append(comps, p)
		}
		comps = append(comps, p[:i])
		p = p[i+1:]
	}
}

func matchSegs(pat, comps []string, dirAlso bool) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				// trailing **: matches zero or more remaining components; with
				// dirAlso the directory itself is covered (zero components).
				return len(comps) > 0 || dirAlso
			}
			for i := 0; i <= len(comps); i++ {
				if matchSegs(pat[1:], comps[i:], dirAlso) {
					return true
				}
			}
			return false
		}
		if len(comps) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], comps[0]); !ok {
			return false
		}
		pat, comps = pat[1:], comps[1:]
	}
	return len(comps) == 0
}

// globSet is an ordered list of globs with a first-segment index.
type globSet struct {
	all     []*glob
	byFirst map[string][]*glob // globs whose first literal segment is the key
	wild    []*glob            // globs with no usable first literal (anchored, or wildcard first segment)
}

func newGlobSet(pats []string) (*globSet, error) {
	s := &globSet{byFirst: map[string][]*glob{}}
	for _, p := range pats {
		g, err := compileGlob(p)
		if err != nil {
			return nil, err
		}
		s.all = append(s.all, g)
		if g.first != "" {
			s.byFirst[g.first] = append(s.byFirst[g.first], g)
		} else {
			s.wild = append(s.wild, g)
		}
	}
	return s, nil
}

func (s *globSet) match(p string) bool { return s.matchComps(splitPath(p)) }

// matchComps matches pre-split components (see splitPath).
func (s *globSet) matchComps(comps []string) bool {
	if s == nil {
		return false
	}
	if len(comps) > 0 {
		for _, g := range s.byFirst[comps[0]] {
			if g.matchComps(comps) {
				return true
			}
		}
	}
	for _, g := range s.wild {
		if g.matchComps(comps) {
			return true
		}
	}
	return false
}

// expand substitutes ~, $XDG_RUNTIME_DIR and {project} in pat. Patterns
// needing an unavailable expansion yield no results.
func expand(pat string, env Env) []string {
	if strings.HasPrefix(pat, "~/") || pat == "~" {
		pat = env.Home + strings.TrimPrefix(pat, "~")
	}
	if strings.Contains(pat, "$XDG_RUNTIME_DIR") {
		if env.RuntimeDir == "" {
			return nil
		}
		pat = strings.ReplaceAll(pat, "$XDG_RUNTIME_DIR", env.RuntimeDir)
	}
	if strings.Contains(pat, "{project}") {
		var out []string
		for _, root := range env.Projects {
			out = append(out, strings.ReplaceAll(pat, "{project}", root))
		}
		return out
	}
	return []string{pat}
}
