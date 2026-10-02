package main

import "testing"

func TestHumanize(t *testing.T) {
	displayNames = entityNames{}
	displayNames.setNames(map[string]map[string]string{
		"ja": {"http://localhost:8720": "学認Issuer", "http://localhost:8701": "NII"},
		"en": {"http://localhost:8720": "GakuNin Issuer", "http://localhost:8701": "NII"},
	})
	defer func() { displayNames = entityNames{} }()
	in := "no valid trust chain for http://localhost:8720: GET http://localhost:8701/fetch?sub=http%3A%2F%2Flocalhost%3A8720 -> 404"
	cases := []struct{ in, lang, want string }{
		{in, "ja", "no valid trust chain for 学認Issuer: GET NII (/fetch?sub=学認Issuer) -> 404"},
		{in, "en", "no valid trust chain for GakuNin Issuer: GET NII (/fetch?sub=GakuNin Issuer) -> 404"},
		{"at http://localhost:8720/token: 401", "en", "at GakuNin Issuer (/token): 401"},
		{"http://localhost:87201/x", "ja", "http://localhost:87201/x"},
	}
	for _, c := range cases {
		if got := Humanize(c.in, c.lang); got != c.want {
			t.Errorf("Humanize(%q, %s) = %q, want %q", c.in, c.lang, got, c.want)
		}
	}
	if got := NameOf("http://localhost:8720/", "en"); got != "GakuNin Issuer" {
		t.Errorf("NameOf = %q", got)
	}
}

func TestMsg(t *testing.T) {
	m := M("日本語", "English")
	if m.In("ja") != "日本語" || m.In("en") != "English" || M("のみ", "").In("en") != "のみ" {
		t.Errorf("Msg.In: %+v", m)
	}
}
