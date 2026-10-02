package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Display names of entity identifiers ("GakuNin Issuer" or its Japanese name instead of
// "http://localhost:8720") in Japanese and English, fetched from the demo console
// (DEMO_CONSOLE /api/entity-names). Without the console the identifiers are shown as-is.

type entityNames struct {
	mu      sync.Mutex
	loaded  bool
	lastTry time.Time
	names   map[string]map[string]string // lang -> entity ID -> name
	encoded *regexp.Regexp
	plain   *regexp.Regexp
}

var displayNames entityNames

// setNames installs the name tables (lang -> entity ID -> name) and builds the matchers.
func (n *entityNames) setNames(names map[string]map[string]string) {
	idSet := map[string]bool{}
	for _, m := range names {
		for id := range m {
			idSet[id] = true
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return len(ids[i]) > len(ids[j]) })
	enc := make([]string, len(ids))
	plain := make([]string, len(ids))
	for i, id := range ids {
		enc[i] = regexp.QuoteMeta(url.QueryEscape(id))
		plain[i] = regexp.QuoteMeta(id)
	}
	n.names = names
	n.encoded = regexp.MustCompile(strings.Join(enc, "|"))
	// entity ID not followed by more port digits, optional trailing path
	n.plain = regexp.MustCompile(`(` + strings.Join(plain, "|") + `)([0-9]?)((?:/[^\s"'<>,;:)\]]*)?)`)
	n.loaded = true
}

func (n *entityNames) load() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.loaded || time.Since(n.lastTry) < 5*time.Second {
		return
	}
	n.lastTry = time.Now()
	console := os.Getenv("DEMO_CONSOLE")
	if console == "" {
		return
	}
	resp, err := (&http.Client{Timeout: time.Second}).Get(strings.TrimSuffix(console, "/") + "/api/entity-names")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var names map[string]map[string]string
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&names) != nil || len(names) == 0 {
		return
	}
	n.setNames(names)
}

func (n *entityNames) lookup(id, lang string) (string, bool) {
	m := n.names[lang]
	if m == nil {
		m = n.names["ja"]
	}
	name, ok := m[id]
	return name, ok
}

// NameOf returns the display name of an entity identifier in lang (or the identifier itself).
func NameOf(id, lang string) string {
	displayNames.load()
	displayNames.mu.Lock()
	defer displayNames.mu.Unlock()
	if name, ok := displayNames.lookup(strings.TrimSuffix(id, "/"), lang); ok {
		return name
	}
	return id
}

// Humanize replaces entity identifiers (also URL-encoded ones and URLs under them) in a message.
func Humanize(s, lang string) string {
	displayNames.load()
	displayNames.mu.Lock()
	defer displayNames.mu.Unlock()
	if !displayNames.loaded || s == "" {
		return s
	}
	encoded := func(s string) string {
		return displayNames.encoded.ReplaceAllStringFunc(s, func(m string) string {
			id, _ := url.QueryUnescape(m)
			name, _ := displayNames.lookup(id, lang)
			return name
		})
	}
	// entity URLs first (their paths may contain URL-encoded entity IDs), then remaining encoded IDs
	s = displayNames.plain.ReplaceAllStringFunc(s, func(m string) string {
		g := displayNames.plain.FindStringSubmatch(m)
		if g[2] != "" { // a different port (e.g. :87201): not this entity
			return m
		}
		name, _ := displayNames.lookup(g[1], lang)
		if g[3] != "" && g[3] != "/" {
			return name + " (" + encoded(g[3]) + ")"
		}
		return name
	})
	return encoded(s)
}
