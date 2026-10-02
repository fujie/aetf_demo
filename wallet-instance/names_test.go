package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestHumanize(t *testing.T) {
	ids := []string{"http://localhost:8720", "http://localhost:8701"}
	names := map[string]string{ids[0]: "学認Issuer", ids[1]: "NII"}
	enc := []string{regexp.QuoteMeta(url.QueryEscape(ids[0])), regexp.QuoteMeta(url.QueryEscape(ids[1]))}
	plain := []string{regexp.QuoteMeta(ids[0]), regexp.QuoteMeta(ids[1])}
	displayNames = entityNames{
		loaded:  true,
		names:   names,
		encoded: regexp.MustCompile(strings.Join(enc, "|")),
		plain:   regexp.MustCompile(`(` + strings.Join(plain, "|") + `)([0-9]?)((?:/[^\s"'<>,;:)\]]*)?)`),
	}
	defer func() { displayNames = entityNames{} }()
	cases := map[string]string{
		"no valid trust chain for http://localhost:8720: GET http://localhost:8701/fetch?sub=http%3A%2F%2Flocalhost%3A8720 -> 404": "no valid trust chain for 学認Issuer: GET NII (/fetch?sub=学認Issuer) -> 404",
		"at http://localhost:8720/token: 401": "at 学認Issuer (/token): 401",
		"http://localhost:87201/x":            "http://localhost:87201/x",
	}
	for in, want := range cases {
		if got := Humanize(in); got != want {
			t.Errorf("Humanize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NameOf("http://localhost:8720/"); got != "学認Issuer" {
		t.Errorf("NameOf = %q", got)
	}
}
