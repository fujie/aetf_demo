package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// UI language (Japanese / English). The web UI uses the same `lang` cookie as the other demo
// entities (cookies on localhost are shared by all ports) and `?lang=ja|en` to switch; without
// either it follows Accept-Language (default Japanese). The CLI uses WALLET_LANG (default ja).

// Msg is a message in Japanese and English.
type Msg struct{ Ja, En string }

// M builds a message in both languages.
func M(ja, en string) Msg { return Msg{Ja: ja, En: en} }

// S builds a language-neutral message (identifiers, URLs, technical details).
func S(format string, args ...any) Msg {
	s := fmt.Sprintf(format, args...)
	return Msg{Ja: s, En: s}
}

// In returns the message in lang.
func (m Msg) In(lang string) string {
	if lang == "en" && m.En != "" {
		return m.En
	}
	return m.Ja
}

// cliLang is the language of the CLI output.
func cliLang() string {
	if strings.HasPrefix(strings.ToLower(os.Getenv("WALLET_LANG")), "en") {
		return "en"
	}
	return "ja"
}

// requestLang returns the language of a web request and whether it was chosen with ?lang=.
func requestLang(r *http.Request) (lang string, fromQuery bool) {
	if q := r.URL.Query().Get("lang"); q == "ja" || q == "en" {
		return q, true
	}
	if c, err := r.Cookie("lang"); err == nil && (c.Value == "ja" || c.Value == "en") {
		return c.Value, false
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))), "en") {
		return "en", false
	}
	return "ja", false
}

// withLang stores a language chosen with ?lang= in the shared cookie.
func withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lang, fromQuery := requestLang(r); fromQuery {
			http.SetCookie(w, &http.Cookie{Name: "lang", Value: lang, Path: "/", MaxAge: 31536000, SameSite: http.SameSiteLaxMode})
		}
		next.ServeHTTP(w, r)
	})
}
