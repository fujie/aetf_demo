package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Every page template renders in both languages (template errors only show up at execution).
func TestTemplatesRenderInBothLanguages(t *testing.T) {
	disp := credentialDisplay{
		Names:       map[string]string{"ja": "学認 学生証明書", "en": "GakuNin Student Credential"},
		IssuerNames: map[string]string{"ja": "学認 Issuer", "en": "GakuNin Issuer"},
		ClaimLabels: map[string]map[string]string{"ja": {"name": "氏名"}, "en": {"name": "Name"}},
	}
	cred := &CredentialView{ID: "c1", ReceivedAt: time.Now(), Issuer: "http://localhost:8720", Display: disp,
		ClaimNames: []string{"name"}, Disclosures: map[string]any{"name": "Taro"}}
	steps := []Step{{OK: true, Title: M("確認", "Checked"), Detail: S("detail")}}
	pages := map[string]any{
		"home":       []*CredentialView{cred},
		"scan":       nil,
		"activity":   nil,
		"result":     map[string]any{"CredentialID": "c1"},
		"offer":      map[string]any{"ID": "x", "Preview": &OfferPreview{Issuer: "http://localhost:8720", Display: disp}},
		"request":    map[string]any{"ID": "x", "Prep": &PresentationPrep{LoTE: &LoadedLoTE{}, RP: &RelyingParty{}, Credential: cred, ClaimOrder: []string{"name"}, Requested: []string{"name"}}},
		"credential": map[string]any{"C": cred, "Payload": "{}"},
	}
	inst := &Instance{}
	want := map[string]string{"ja": "クレデンシャル", "en": "Credentials"}
	for _, lang := range []string{"ja", "en"} {
		for name, data := range pages {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/?lang="+lang, nil)
			inst.render(w, r, name, pageData{Title: name, Data: data, Steps: steps})
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, want[lang]) {
				t.Errorf("%s/%s: status %d, body %.300s", lang, name, w.Code, body)
			}
		}
	}
}
