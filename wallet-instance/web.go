package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Web wallet UI ("serve"). Single-user demo: operations are serialised.

type webState struct {
	mu       sync.Mutex // serialises wallet operations
	offers   map[string]*OfferPreview
	requests map[string]*PresentationPrep
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// baseFuncs are the template functions; the language-dependent ones are replaced per request
// (see langFuncs) on a clone of the templates.
var baseFuncs = template.FuncMap{
	"join": strings.Join,
	"time": func(t time.Time) string { return t.Local().Format("01/02 15:04:05") },
	"statusName": func(s *StatusResult) string {
		if s == nil {
			return "?"
		}
		return StatusTypeName(s.Status)
	},
	"statusClass": func(s *StatusResult) string {
		if s == nil {
			return "warn"
		}
		if s.Status == 0 {
			return "ok"
		}
		return "ng"
	},
	"contains": slices.Contains[[]string],
	"short": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
}

// langFuncs are the template functions bound to the language of one request.
func langFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"lang": func() string { return lang },
		"t": func(ja, en string) string {
			if lang == "en" {
				return en
			}
			return ja
		},
		"msg":      func(m Msg) string { return m.In(lang) },
		"name":     func(id string) string { return NameOf(id, lang) },
		"humanize": func(s string) string { return Humanize(s, lang) },
		"chain": func(p []string) string {
			names := make([]string, len(p))
			for i, id := range p {
				names[i] = NameOf(id, lang)
			}
			return strings.Join(names, " → ")
		},
		"dname":   func(d credentialDisplay) string { return d.NameIn(lang) },
		"dissuer": func(d credentialDisplay) string { return d.IssuerNameIn(lang) },
		"label":   func(d credentialDisplay, claim string) string { return d.LabelIn(lang, claim) },
	}
}

var tpl = func() *template.Template {
	funcs := template.FuncMap{}
	for k, v := range baseFuncs {
		funcs[k] = v
	}
	for k, v := range langFuncs("ja") {
		funcs[k] = v
	}
	t := template.Must(template.Must(template.New("layout").Funcs(funcs).Parse(layoutTpl)).Parse(stepsTpl))
	for name, body := range map[string]string{
		"home": homeTpl, "scan": scanTpl, "offer": offerTpl, "request": requestTpl,
		"result": resultTpl, "credential": credentialTpl, "activity": activityTpl,
	} {
		template.Must(t.New(name).Parse(body))
	}
	return t
}()

type pageData struct {
	Title   string
	Inst    *Instance
	Expiry  time.Time
	Data    any
	Steps   []Step
	Error   string
	Flash   string
	Console string
	// Wallet Instance status (Status List entry referenced by the Wallet Attestation)
	WIStatus *StatusResult
	Lang     string
	// links to the current page in Japanese / English
	LangJa, LangEn string
}

// tr returns ja or en depending on lang.
func tr(lang, ja, en string) string {
	if lang == "en" {
		return en
	}
	return ja
}

func (i *Instance) render(w http.ResponseWriter, r *http.Request, name string, d pageData) {
	lang, _ := requestLang(r)
	d.Inst = i
	d.Expiry = i.AttestationExpiry()
	d.Console = getenv("DEMO_CONSOLE", "")
	d.Lang = lang
	for _, l := range []string{"ja", "en"} {
		u := *r.URL
		q := u.Query()
		q.Set("lang", l)
		u.RawQuery = q.Encode()
		if r.Method != http.MethodGet {
			u.Path, u.RawQuery = "/", "lang="+l // a POST result cannot be re-requested
		}
		if l == "ja" {
			d.LangJa = u.RequestURI()
		} else {
			d.LangEn = u.RequestURI()
		}
	}
	t, err := tpl.Clone()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	t.Funcs(langFuncs(lang))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var body strings.Builder
	if err := t.ExecuteTemplate(&body, name, d); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", struct {
		pageData
		Body template.HTML
	}{d, template.HTML(body.String())}); err != nil {
		log.Println(err)
	}
}

func (i *Instance) serve(port string) error {
	installAttestationTransport(i)
	st := &webState{offers: map[string]*OfferPreview{}, requests: map[string]*PresentationPrep{}}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		lang, _ := requestLang(r)
		creds, err := i.Credentials(true)
		d := pageData{Title: tr(lang, "ウォレット", "Wallet"), Data: creds, Flash: r.URL.Query().Get("flash")}
		d.WIStatus, _ = i.AttestationStatus()
		if err != nil {
			d.Error = err.Error()
		}
		i.render(w, r, "home", d)
	})

	mux.HandleFunc("GET /scan", func(w http.ResponseWriter, r *http.Request) {
		lang, _ := requestLang(r)
		i.render(w, r, "scan", pageData{Title: tr(lang, "読み取り", "Scan")})
	})

	// Dispatch a pasted / deep-linked URI by scheme
	mux.HandleFunc("GET /open", func(w http.ResponseWriter, r *http.Request) {
		uri := strings.TrimSpace(r.URL.Query().Get("uri"))
		switch {
		case strings.HasPrefix(uri, "openid-credential-offer:"):
			http.Redirect(w, r, "/receive?offer="+url.QueryEscape(uri), http.StatusSeeOther)
		case strings.HasPrefix(uri, "openid4vp:"):
			http.Redirect(w, r, "/present?request="+url.QueryEscape(uri), http.StatusSeeOther)
		default:
			lang, _ := requestLang(r)
			i.render(w, r, "scan", pageData{Title: tr(lang, "読み取り", "Scan"),
				Error: tr(lang, "openid-credential-offer:// または openid4vp: で始まる URI を入力してください", "Enter a URI starting with openid-credential-offer:// or openid4vp:")})
		}
	})

	mux.HandleFunc("GET /receive", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		preview, err := i.PreviewOffer(r.URL.Query().Get("offer"))
		lang, _ := requestLang(r)
		d := pageData{Title: tr(lang, "クレデンシャルの受け取り", "Receive credential"), Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
			i.render(w, r, "result", d)
			return
		}
		id := newID()
		st.offers[id] = preview
		d.Data = map[string]any{"ID": id, "Preview": preview}
		i.render(w, r, "offer", d)
	})

	mux.HandleFunc("POST /receive", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		preview := st.offers[r.FormValue("id")]
		delete(st.offers, r.FormValue("id"))
		if preview == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		i.steps.begin()
		saved, err := i.AcceptOffer(preview)
		lang, _ := requestLang(r)
		d := pageData{Title: tr(lang, "クレデンシャルの受け取り", "Receive credential"), Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Flash = fmt.Sprintf(tr(lang, "%s を受け取りました", "Received %s"), preview.Display.NameIn(lang))
			d.Data = map[string]any{"CredentialID": saved.Entry.Id}
		}
		i.render(w, r, "result", d)
	})

	mux.HandleFunc("GET /present", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		prep, err := i.PreparePresentation(r.URL.Query().Get("request"))
		lang, _ := requestLang(r)
		d := pageData{Title: tr(lang, "提示リクエスト", "Presentation request"), Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
			i.render(w, r, "result", d)
			return
		}
		id := newID()
		st.requests[id] = prep
		d.Data = map[string]any{"ID": id, "Prep": prep}
		i.render(w, r, "request", d)
	})

	mux.HandleFunc("POST /present", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		prep := st.requests[r.FormValue("id")]
		delete(st.requests, r.FormValue("id"))
		if prep == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		lang, _ := requestLang(r)
		if r.FormValue("action") == "deny" {
			i.info(M("提示を拒否", "Presentation declined"), S("%s", prep.ClientID))
			http.Redirect(w, r, "/?flash="+url.QueryEscape(tr(lang, "提示を拒否しました", "Presentation declined")), http.StatusSeeOther)
			return
		}
		i.steps.begin()
		redirect, err := i.SubmitPresentation(prep, r.Form["claim"])
		d := pageData{Title: tr(lang, "提示結果", "Presentation result"), Steps: i.steps.take(), Data: map[string]any{"Redirect": redirect}}
		if err != nil {
			d.Error = err.Error()
		} else {
			d.Flash = fmt.Sprintf(tr(lang, "%s に提示しました", "Presented to %s"), prep.RP.CommonName)
		}
		i.render(w, r, "result", d)
	})

	mux.HandleFunc("GET /credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		creds, err := i.Credentials(true)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for _, c := range creds {
			if c.ID == r.PathValue("id") {
				payload, _ := json.MarshalIndent(c.Payload, "", "  ")
				lang, _ := requestLang(r)
				i.render(w, r, "credential", pageData{Title: c.Display.NameIn(lang), Data: map[string]any{"C": c, "Payload": string(payload)}})
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("POST /attest", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		i.steps.begin()
		err := i.RefreshAttestation()
		d := pageData{Title: "Wallet Attestation", Steps: i.steps.take()}
		if err != nil {
			d.Error = err.Error()
		} else {
			lang, _ := requestLang(r)
			d.Flash = tr(lang, "Wallet Attestation を取得しました", "Obtained a Wallet Attestation")
		}
		i.render(w, r, "result", d)
	})

	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		_ = i.ResetCredentials()
		lang, _ := requestLang(r)
		http.Redirect(w, r, "/?flash="+url.QueryEscape(tr(lang, "クレデンシャルを削除しました", "Deleted the credentials")), http.StatusSeeOther)
	})

	mux.HandleFunc("GET /activity", func(w http.ResponseWriter, r *http.Request) {
		lang, _ := requestLang(r)
		i.render(w, r, "activity", pageData{Title: tr(lang, "アクティビティ", "Activity"), Steps: i.steps.recent(100)})
	})

	// Summary for the demo console
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		creds, _ := i.Credentials(false)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"wallet_instance_id": i.state.WalletInstanceID,
			"attestation_exp":    i.AttestationExpiry(),
			"credentials":        len(creds),
		})
	})

	// WALLET_LISTEN_ADDR: listen address when deployed behind the dispatcher (e.g. 127.0.0.1:8760)
	addr := getenv("WALLET_LISTEN_ADDR", "localhost:"+port)
	fmt.Printf("Web wallet UI: http://%s\n", addr)
	return http.ListenAndServe(addr, withLang(mux))
}

// ---- templates ---------------------------------------------------------------------------------

const layoutTpl = `<!doctype html><html lang="{{lang}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - GakuNin Wallet</title>
<style>
 :root{--c:#155e86;--bg:#e9eef2;--fg:#1f2328;--mut:#5b6670;--ok:#1a7f37;--ng:#cf222e;--warn:#9a6700;--card:#fff}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;color:var(--fg)}
 .phone{max-width:430px;margin:0 auto;min-height:100vh;background:#f7f9fb;box-shadow:0 0 24px rgba(0,0,0,.12);display:flex;flex-direction:column}
 header{background:var(--c);color:#fff;padding:14px 16px;display:flex;align-items:center;gap:10px}
 header a{color:#fff;text-decoration:none}
 header .t{font-weight:700;font-size:17px;flex:1}
 main{padding:14px 14px 90px;flex:1}
 nav{position:sticky;bottom:0;background:#fff;border-top:1px solid #d0d7de;display:flex}
 nav a{flex:1;text-align:center;padding:10px 0 12px;color:var(--mut);text-decoration:none;font-size:12px}
 nav a b{display:block;font-size:20px;line-height:1.3}
 .card{background:var(--card);border-radius:12px;padding:14px;margin:0 0 12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
 .vc{border-radius:14px;padding:16px;color:#fff;margin-bottom:12px;display:block;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.18)}
 .vc .n{font-weight:700;font-size:17px}.vc .i{opacity:.85;font-size:12px;margin-top:2px}
 .vc .h{font-size:22px;margin-top:18px;font-weight:600}
 .badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700;background:#fff}
 .badge.ok{color:var(--ok)}.badge.ng{color:var(--ng)}.badge.warn{color:var(--warn)}
 .btn{display:block;width:100%;border:0;border-radius:10px;padding:13px;font-size:15px;font-weight:600;background:var(--c);color:#fff;text-align:center;text-decoration:none;cursor:pointer;margin-top:8px}
 .btn.sec{background:#fff;color:var(--c);border:1px solid var(--c)}
 .btn.danger{background:#fff;color:var(--ng);border:1px solid var(--ng)}
 .mut{color:var(--mut);font-size:12px}
 code{font-size:11px;background:#eef1f4;border-radius:4px;padding:1px 4px;word-break:break-all}
 table{width:100%;border-collapse:collapse;font-size:14px} td,th{padding:7px 4px;border-bottom:1px solid #eef1f4;text-align:left;vertical-align:top}
 th{color:var(--mut);font-weight:500;width:40%}
 .steps{list-style:none;padding:0;margin:0}
 .steps li{padding:8px 0 8px 28px;position:relative;border-bottom:1px solid #eef1f4;font-size:14px}
 .steps li:before{position:absolute;left:4px;top:8px;font-weight:700}
 .steps li.ok:before{content:"✓";color:var(--ok)} .steps li.ng:before{content:"✗";color:var(--ng)} .steps li.info:before{content:"→";color:var(--mut)}
 .steps .d{display:block;color:var(--mut);font-size:12px;word-break:break-all}
 .flash{background:#dafbe1;color:var(--ok);border-radius:10px;padding:10px 12px;margin-bottom:12px;font-weight:600}
 .error{background:#ffebe9;color:var(--ng);border-radius:10px;padding:10px 12px;margin-bottom:12px;word-break:break-all}
 textarea{width:100%;min-height:120px;border:1px solid #d0d7de;border-radius:10px;padding:10px;font-size:13px}
 label.claim{display:flex;gap:10px;align-items:flex-start;padding:9px 2px;border-bottom:1px solid #eef1f4}
 label.claim input{width:20px;height:20px;margin-top:2px}
 label.claim .v{color:var(--mut);font-size:12px;display:block}
 .tag{display:inline-block;font-size:11px;border-radius:6px;padding:1px 6px;background:#fff4d4;color:var(--warn);margin-left:4px}
 h2{font-size:15px;margin:4px 0 10px}
 header .lang{font-size:12px;color:#cfe3ef} header .lang a{color:#cfe3ef;text-decoration:underline}
</style></head><body><div class="phone">
<header><a href="/">◀</a><span class="t">{{.Title}}</span><span class="lang">{{if eq .Lang "ja"}}<b>日本語</b> | <a href="{{.LangEn}}">English</a>{{else}}<a href="{{.LangJa}}">日本語</a> | <b>English</b>{{end}}</span></header>
<main>
{{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
{{if .Error}}<div class="error">✗ {{humanize .Error}}</div>{{end}}
{{.Body}}
</main>
<nav><a href="/"><b>▤</b>{{t "クレデンシャル" "Credentials"}}</a><a href="/scan"><b>⌗</b>{{t "読み取り" "Scan"}}</a><a href="/activity"><b>≡</b>{{t "アクティビティ" "Activity"}}</a>{{if .Console}}<a href="{{.Console}}" target="_blank"><b>◎</b>{{t "デモ" "Demo"}}</a>{{end}}</nav>
</div></body></html>`

const homeTpl = `
<div class="card">
 <h2>Wallet Instance</h2>
 {{if .Inst.InstanceID}}
  <div class="mut">ID <code>{{short .Inst.InstanceID 60}}</code></div>
  <div class="mut" style="margin-top:4px">Wallet Attestation:
   {{if .Expiry.IsZero}}<b style="color:var(--ng)">{{t "なし" "none"}}</b>{{else}}{{t "有効期限" "expires"}} {{time .Expiry}}{{end}}</div>
  {{with .WIStatus}}<div class="mut" style="margin-top:4px">{{t "Wallet Instance の状態" "Wallet Instance status"}}:
   <span class="badge {{statusClass .}}" style="border:1px solid #d0d7de">{{statusName .}}</span> (Status List idx {{.Idx}})</div>{{end}}
 {{else}}<div class="mut">{{t "未登録です。Wallet Provider に登録して Wallet Attestation を取得してください。" "Not registered. Register with the Wallet Provider to obtain a Wallet Attestation."}}</div>{{end}}
 <form method="post" action="/attest"><button class="btn sec">{{if .Inst.InstanceID}}{{t "Wallet Attestation を再取得" "Fetch a new Wallet Attestation"}}{{else}}{{t "Wallet Provider に登録" "Register with the Wallet Provider"}}{{end}}</button></form>
</div>
{{range .Data}}
 <a class="vc" href="/credentials/{{.ID}}" style="background:{{.Display.Background}};color:{{.Display.TextColor}}">
  <div style="display:flex;justify-content:space-between;align-items:start">
   <div><div class="n">{{dname .Display}}</div><div class="i">{{or (dissuer .Display) (name .Issuer)}}</div></div>
   <span class="badge {{statusClass .Status}}">{{statusName .Status}}</span>
  </div>
  <div class="h">{{index .Disclosures "name"}}</div>
  <div class="i">{{index .Disclosures "organization"}} {{index .Disclosures "department"}}</div>
  <div class="i" style="margin-top:6px">{{t "受領" "Received"}} {{time .ReceivedAt}}</div>
 </a>
{{else}}
 <div class="card mut">{{t "クレデンシャルはまだありません。学認Issuer の Credential Offer を読み取ってください。" "No credentials yet. Scan a Credential Offer from the GakuNin Issuer."}}</div>
{{end}}
<a class="btn" href="/scan">{{t "Offer / 提示リクエストを読み取る" "Scan an offer / presentation request"}}</a>
{{if .Data}}<form method="post" action="/reset" onsubmit="return confirm({{t "保存済みクレデンシャルを削除しますか?" "Delete the stored credentials?"}})"><button class="btn danger">{{t "クレデンシャルを全て削除" "Delete all credentials"}}</button></form>{{end}}`

const scanTpl = `
<div class="card">
 <h2>{{t "URI を貼り付け" "Paste a URI"}}</h2>
 <p class="mut">{{if eq lang "en"}}Paste an Issuer's <code>openid-credential-offer://</code> or a Verifier's <code>openid4vp:</code> URI
 (or use the "Open in Web Wallet" button on the Issuer / Verifier pages).{{else}}Issuer の <code>openid-credential-offer://</code> または Verifier の <code>openid4vp:</code> を貼り付けてください。
 (Issuer / Verifier の画面の「Web Wallet で開く」ボタンからも直接開けます){{end}}</p>
 <form method="get" action="/open"><textarea name="uri" placeholder="openid-credential-offer://?credential_offer=... / openid4vp:?client_id=..."></textarea>
 <button class="btn">{{t "開く" "Open"}}</button></form>
</div>`

const stepsTpl = `{{define "steps"}}{{if .}}<div class="card"><h2>{{t "検証ステップ" "Verification steps"}}</h2><ul class="steps">{{range .}}<li class="{{if .Info}}info{{else if .OK}}ok{{else}}ng{{end}}">{{msg .Title}}{{with msg .Detail}}<span class="d">{{.}}</span>{{end}}</li>{{end}}</ul></div>{{end}}{{end}}`

const offerTpl = `
{{$p := index .Data "Preview"}}
<div class="vc" style="background:{{$p.Display.Background}};color:{{$p.Display.TextColor}}">
 <div class="n">{{dname $p.Display}}</div><div class="i">{{dissuer $p.Display}}</div>
 <div class="i" style="margin-top:14px">{{t "発行者" "Issuer"}} {{name $p.Issuer}}</div>
</div>
<div class="card"><h2>{{t "発行者" "Issuer"}}</h2>
 <table><tr><th>Issuer</th><td>{{name $p.Issuer}}</td></tr>
 <tr><th>{{t "信頼チェーン" "Trust chain"}}</th><td><span class="badge ok" style="background:#dafbe1">OpenID Federation</span><div class="mut" style="margin-top:4px">{{chain $p.IssuerChain}}</div></td></tr>
 <tr><th>{{t "種別" "Type"}}</th><td>{{join $p.ConfigurationID ", "}}</td></tr></table>
</div>
{{template "steps" .Steps}}
<form method="post" action="/receive"><input type="hidden" name="id" value="{{index .Data "ID"}}">
 <button class="btn">{{t "受け取る" "Accept"}}</button></form>
<a class="btn sec" href="/">{{t "キャンセル" "Cancel"}}</a>
<p class="mut">{{t "受け取り時に Wallet Attestation と PoP を Issuer のトークンエンドポイントへ送ります。" "On accepting, the Wallet Attestation and a PoP are sent to the Issuer's token endpoint."}}</p>`

const requestTpl = `
{{$p := index .Data "Prep"}}
<div class="card"><h2>{{t "提示を求めている相手" "Requested by"}}</h2>
 <div style="font-size:18px;font-weight:700">{{$p.RP.CommonName}}</div>
 <div class="mut">{{$p.RP.Organization}} ({{$p.RP.OrganizationIdentifier}})</div>
 <table style="margin-top:8px">
  <tr><th>client_id</th><td><code>{{$p.ClientID}}</code></td></tr>
  <tr><th>{{t "アクセス証明書" "Access certificate"}}</th><td><span class="badge ok" style="background:#dafbe1">ETSI TS 119 411-8</span><div class="mut">policy {{$p.RP.Policy}}<br>{{t "発行" "issued by"}} {{$p.RP.AccessCA}}</div></td></tr>
  <tr><th>Trust List</th><td><span class="badge ok" style="background:#dafbe1">ETSI TS 119 602</span><div class="mut">{{$p.LoTE.SchemeOperator}} (seq {{$p.LoTE.SequenceNumber}})<br>{{t "署名者" "signer"}}: {{chain $p.LoTE.FederationPath}}</div></td></tr>
 </table>
</div>
<form method="post" action="/present"><input type="hidden" name="id" value="{{index .Data "ID"}}">
<div class="card"><h2>{{t "開示する属性" "Attributes to disclose"}} ({{dname $p.Credential.Display}})</h2>
 {{range $c := $p.ClaimOrder}}
  <label class="claim"><input type="checkbox" name="claim" value="{{$c}}" {{if contains $p.Requested $c}}checked data-required="1"{{end}}>
   <span>{{label $p.Credential.Display $c}}{{if contains $p.Requested $c}}<span class="tag">{{t "要求" "requested"}}</span>{{end}}<span class="v">{{$p.Credential.Value $c}}</span></span></label>
 {{end}}
 <div id="warn" class="error" style="display:none;margin-top:10px">{{t "Verifier が要求した属性を外しています。DCQL の要求を満たさないため Verifier に拒否される可能性があります。" "You unchecked an attribute requested by the Verifier. The DCQL query is not satisfied, so the Verifier may reject the presentation."}}</div>
 <p class="mut">{{t "チェックした属性だけが選択的開示 (SD-JWT) で提示されます。Key Binding JWT で本人のウォレットからの提示であることを示します。" "Only the checked attributes are disclosed (SD-JWT selective disclosure). A Key Binding JWT shows the presentation comes from the holder's wallet."}}</p>
</div>
<script>
document.querySelectorAll('input[name=claim]').forEach((el) => el.addEventListener('change', () => {
  const missing = [...document.querySelectorAll('input[data-required]')].some((x) => !x.checked)
  document.getElementById('warn').style.display = missing ? 'block' : 'none'
}))
</script>
{{template "steps" .Steps}}
<button class="btn" name="action" value="present">{{t "提示する" "Present"}}</button>
<button class="btn sec" name="action" value="deny">{{t "拒否する" "Decline"}}</button>
</form>`

const resultTpl = `
{{template "steps" .Steps}}
{{with .Data}}{{with index . "CredentialID"}}<a class="btn" href="/credentials/{{.}}">{{t "受け取ったクレデンシャルを見る" "View the received credential"}}</a>{{end}}{{end}}
{{with .Data}}{{with index . "Redirect"}}<a class="btn sec" href="{{.}}" target="_blank">{{t "Verifier の結果画面を開く" "Open the Verifier's result page"}}</a>{{end}}{{end}}
<a class="btn sec" href="/">{{t "ホームへ" "Home"}}</a>`

const credentialTpl = `
{{$c := index .Data "C"}}
<div class="vc" style="background:{{$c.Display.Background}};color:{{$c.Display.TextColor}}">
 <div style="display:flex;justify-content:space-between"><div class="n">{{dname $c.Display}}</div><span class="badge {{statusClass $c.Status}}">{{statusName $c.Status}}</span></div>
 <div class="i">{{dissuer $c.Display}}</div>
</div>
<div class="card"><h2>{{t "属性 (選択的開示が可能)" "Attributes (selectively disclosable)"}}</h2><table>
 {{range $k := $c.ClaimNames}}<tr><th>{{label $c.Display $k}}</th><td>{{$c.Value $k}}</td></tr>{{end}}
</table></div>
<div class="card"><h2>{{t "状態 (Token Status List)" "Status (Token Status List)"}}</h2>
 {{with $c.Status}}<table><tr><th>{{t "状態" "Status"}}</th><td><span class="badge {{statusClass $c.Status}}" style="border:1px solid #d0d7de">{{statusName $c.Status}}</span></td></tr>
  <tr><th>idx</th><td>{{.Idx}}</td></tr><tr><th>Status List</th><td>{{humanize .URI}}</td></tr>
  <tr><th>Status Issuer</th><td class="mut">{{chain .ChainPath}}</td></tr></table>
 {{else}}<div class="error">{{humanize $c.StatusErr}}</div>{{end}}
</div>
<div class="card"><h2>{{t "Issuer 署名部 (SD-JWT payload)" "Issuer-signed part (SD-JWT payload)"}}</h2><pre style="font-size:11px;white-space:pre-wrap;word-break:break-all">{{index .Data "Payload"}}</pre></div>`

const activityTpl = `{{template "steps" .Steps}}{{if not .Steps}}<div class="card mut">{{t "まだアクティビティはありません。" "No activity yet."}}</div>{{end}}`
